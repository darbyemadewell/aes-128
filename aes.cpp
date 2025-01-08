/****************************
 * ECE 592 (080) Assignment 1: Implementing AES
 * Author: D. E. Madewell
 * Date: 6 Sept 2023
 * Professor: Aydin Aysu
****************************/

#include <iomanip>
#include <iostream>
#include <string>
#include <map>

using namespace std;

/*********************** Constants ***********************/

string input_str = "00112233445566778899AABBCCDDEEFF";

string round_key_list[11] = {
	"000102030405060708090a0b0c0d0e0f", 
	"d6aa74fdd2af72fadaa678f1d6ab76fe",
	"b692cf0b643dbdf1be9bc5006830b3fe",
	"b6ff744ed2c2c9bf6c590cbf0469bf41",
	"47f7f7bc95353e03f96c32bcfd058dfd",
	"3caaa3e8a99f9deb50f3af57adf622aa",
	"5e390f7df7a69296a7553dc10aa31f6b",
	"14f9701ae35fe28c440adf4d4ea9c026",
	"47438735a41c65b9e016baf4aebf7ad2",
	"549932d1f08557681093ed9cbe2c974e",
	"13111d7fe3944a17f307a78b4d2b30c5"
};

unsigned int x02[8] = {0, 1, 0, 0, 0, 0, 0, 0};
unsigned int x03[8] = {1, 1, 0, 0, 0, 0, 0, 0};
unsigned int x09[8] = {1, 0, 0, 1, 0, 0, 0, 0};
unsigned int x0b[8] = {1, 1, 0, 1, 0, 0, 0, 0};
unsigned int x0d[8] = {1, 0, 1, 1, 0, 0, 0, 0};
unsigned int x0e[8] = {0, 1, 1, 1, 0, 0, 0, 0};

unsigned int s_box_array[256], inverse_s_box_array[256];

/************************* Matrices *************************/

struct matrix {
	/* 128 bit matrix structure using round 0 key: 
	   {{0x00, 0x01, 0x02, 0x03}, 
	    {0x04, 0x05, 0x06, 0x07}, 
	    {0x08, 0x09, 0x0A, 0x0B}, 
	    {0x0C, 0x0D, 0x0E, 0x0F}} */

	unsigned int arr[4][4];
};

void print_matrix(struct matrix x, string delimiter = "") {
	for(int ii = 0; ii < 4; ii++) {
		for(int jj = 0; jj < 4; jj++) {
			printf("%02x", x.arr[jj][ii]);
			cout << delimiter;
		}
	}
	cout << '\n';
}

struct matrix str_to_matrix(string str) {
	struct matrix new_matrix;

	for(int ii = 0; ii < 4; ii++) {
		for(int jj = 0; jj < 4; jj++) {
			int index = 2 * (4 * ii + jj);
			new_matrix.arr[jj][ii] = stoi(str.substr(index, 2), 0, 16);
		}
	}

	return new_matrix;
}

/************************* Helpers **************************/

unsigned int bitwise_cyclic_shift_left(unsigned int x, int distance) {
	unsigned int output = x;
	
	for(int ii = 0; ii < distance; ii++) {
		if((output & 0x80) == 0x80) {
			output = output << 1;
			output |= 0x01;
		} else {
			output = output << 1;
		}
	}

	return output & 0xFF;
}

unsigned int perform_affine_transformation(unsigned int x) {
	// Idea for this algorithm pulled from: https://crypto.stackexchange.com/questions/56472/aes-s-box-calculation
	return x ^ bitwise_cyclic_shift_left(x, 1) ^ bitwise_cyclic_shift_left(x, 2) ^ bitwise_cyclic_shift_left(x, 3) ^ bitwise_cyclic_shift_left(x, 4) ^ 0b01100011;
}

unsigned int multiply_polynomials(unsigned int x[8], unsigned int y[8]) {
	int result_len = 15;
	unsigned int result[result_len];

	for(int ii = 0; ii < result_len; ii++) {
		result[ii] = 0;
	}

	for(int ii = 0; ii < 8; ii++) {
		for(int jj = 0; jj < 8; jj++) {
			result[ii+jj] ^= x[ii] * y[jj];
		}
	}
	
	// TODO: Can this be simplified?
	for(int ii = 8; ii < result_len; ii++) {
		if(result[ii] == 1) {
			int diff = ii - 8;
			result[diff] += 1;
			result[diff+1] += 1;
			result[diff+3] += 1;
			result[diff+4] += 1;
		}
		result[ii] = 0;
	}
	for(int ii = 8; ii < result_len; ii++) {
		if(result[ii] == 1) {
			int diff = ii - 8;
			result[diff] += 1;
			result[diff+1] += 1;
			result[diff+3] += 1;
			result[diff+4] += 1;
		}
		result[ii] = 0;
	}

	for(int ii = 0; ii < result_len; ii++) {
		result[ii] %= 2;
	}

	unsigned int result_int = 0;
	for(int ii = 0; ii < 8; ii++) {
		result_int |= result[ii] << ii;
	}

	return result_int;

}

void get_binary_array(unsigned int input, unsigned int output[8]) {
	for (int ii = 0; ii < 8; ii++) {
		output[ii] = (input >> ii) & 0x1;
	}
}

unsigned int get_multiplicative_inverse(unsigned int x) {
	// TODO: Look into Binary GCD algorithm
	unsigned int a[8], b[8];
	unsigned int multiplicative_inverse = 0;
	unsigned int mult;

	get_binary_array(x, a);

	for(unsigned int ii = 0; ii < 256; ii++) {
		get_binary_array(ii, b);
		mult = multiply_polynomials(a, b);
		if(mult == 1) {
			multiplicative_inverse = ii;
			break;
		}
	}
	return multiplicative_inverse;	
}

void cyclic_shift_left(unsigned int input[4], unsigned int output[4], int distance) {
	for(int ii = 0; ii < 4; ii++) {
		int new_index = ii - distance;

		if(new_index < 0) {
			new_index = 4 + new_index;
		}

		output[new_index] = input[ii];
	}
}

void cyclic_shift_right(unsigned int input[4], unsigned int output[4], int distance) {
	for(int ii = 0; ii < 4; ii++) {
		int new_index = ii + distance;

		if(new_index > 3) {
			new_index = new_index - 4;
		}

		output[new_index] = input[ii];
	}
}

void mix_column(unsigned int input[4], unsigned int output[4]) {
	unsigned int input_0[8], input_1[8], input_2[8], input_3[8];
	get_binary_array(input[0], input_0);
	get_binary_array(input[1], input_1);
	get_binary_array(input[2], input_2);
	get_binary_array(input[3], input_3);

	output[0] = multiply_polynomials(x02, input_0) ^ multiply_polynomials(x03, input_1) ^ input[2] ^ input[3];
	output[1] = input[0] ^ multiply_polynomials(x02, input_1) ^ multiply_polynomials(x03, input_2) ^ input[3];
	output[2] = input[0] ^ input[1] ^ multiply_polynomials(x02, input_2) ^ multiply_polynomials(x03, input_3);
	output[3] = multiply_polynomials(x03, input_0) ^ input[1] ^ input[2] ^ multiply_polynomials(x02, input_3);
}

void inv_mix_column(unsigned int input[4], unsigned int output[4]) {
	unsigned int input_0[8], input_1[8], input_2[8], input_3[8];
	get_binary_array(input[0], input_0);
	get_binary_array(input[1], input_1);
	get_binary_array(input[2], input_2);
	get_binary_array(input[3], input_3);

	output[0] = multiply_polynomials(x0e, input_0) ^ multiply_polynomials(x0b, input_1) ^ multiply_polynomials(x0d, input_2) ^ multiply_polynomials(x09, input_3);
	output[1] = multiply_polynomials(x09, input_0) ^ multiply_polynomials(x0e, input_1) ^ multiply_polynomials(x0b, input_2) ^ multiply_polynomials(x0d, input_3);
	output[2] = multiply_polynomials(x0d, input_0) ^ multiply_polynomials(x09, input_1) ^ multiply_polynomials(x0e, input_2) ^ multiply_polynomials(x0b, input_3);
	output[3] = multiply_polynomials(x0b, input_0) ^ multiply_polynomials(x0d, input_1) ^ multiply_polynomials(x09, input_2) ^ multiply_polynomials(x0e, input_3);

}

/******************* AES Encryption Steps ********************/

struct encryption_round {
	struct matrix start;
	struct matrix s_box;
	struct matrix s_row;
	struct matrix m_col;
};

struct matrix add_round_key(struct matrix a, struct matrix b) {
	struct matrix c;

	for(int ii = 0; ii < 4; ii++) {
		for(int jj = 0; jj < 4; jj++) {
			c.arr[ii][jj] = a.arr[ii][jj] ^ b.arr[ii][jj];
		}
	}

	return c;
}

struct matrix sub_bytes(struct matrix input) {
	struct matrix output;

	for(int ii = 0; ii < 4; ii++) {
		for(int jj = 0; jj < 4; jj++) {
			output.arr[ii][jj] = s_box_array[input.arr[ii][jj]];
		}
	}

	return output;
}

struct matrix shift_rows(struct matrix input) {
	struct matrix output;

	for(int ii = 0; ii < 4; ii++) {
		for(int jj = 0; jj < 4; jj++) {
			cyclic_shift_left(input.arr[ii], output.arr[ii], ii);
		}
	}

	return output;
}

struct matrix mix_columns(struct matrix input) {
	struct matrix output;
	unsigned int input_column[4], output_column[4];

	for(int ii = 0; ii < 4; ii++) {
		for(int jj = 0; jj < 4; jj++) {
			input_column[jj] = input.arr[jj][ii];
		}

		mix_column(input_column, output_column);

		for(int jj = 0; jj < 4; jj++) {
			output.arr[jj][ii] = output_column[jj];
		}
	}

	return output;
}

/******************** AES Decryption Steps ********************/

struct decryption_round {
	struct matrix start;
	struct matrix inv_s_row;
	struct matrix inv_s_box;
	struct matrix a_key;
};

struct matrix inv_shift_rows(struct matrix input) {
	struct matrix output;

	for(int ii = 0; ii < 4; ii++) {
		for(int jj = 0; jj < 4; jj++) {
			cyclic_shift_right(input.arr[ii], output.arr[ii], ii);
		}
	}

	return output;
}

struct matrix inv_sub_bytes(struct matrix input) {
	struct matrix output;

	for(int ii = 0; ii < 4; ii++) {
		for(int jj = 0; jj < 4; jj++) {
			output.arr[ii][jj] = inverse_s_box_array[input.arr[ii][jj]];
		}
	}

	return output;
}

struct matrix inv_mix_columns(struct matrix input) {
	struct matrix output;
	unsigned int input_column[4], output_column[4];

	for(int ii = 0; ii < 4; ii++) {
		for(int jj = 0; jj < 4; jj++) {
			input_column[jj] = input.arr[jj][ii];
		}

		inv_mix_column(input_column, output_column);

		for(int jj = 0; jj < 4; jj++) {
			output.arr[jj][ii] = output_column[jj];
		}
	}

	return output;
}

/*********************** AES Rounds ************************/

int main() {
	struct matrix input;
	struct matrix output_ciphertext, output_plaintext;
	struct encryption_round encryption[11];
	struct decryption_round decryption[11];

	for(unsigned int ii = 0; ii < 256; ii++) {
		unsigned int s_box_value = perform_affine_transformation(get_multiplicative_inverse(ii));
		s_box_array[ii] = s_box_value;
		inverse_s_box_array[s_box_value] = ii;
	}

	input = str_to_matrix(input_str);
	cout << "Input plaintext: ";
	print_matrix(input);

	/************************** Encryption ************************/
	
	/* Initial Transformation:
	   * AddRoundKey */

	encryption[1].start = add_round_key(input, str_to_matrix(round_key_list[0]));

	/* Cipher Round:
	   * SubBytes
	   * ShiftRows
	   * MixColumns
	   * AddRoundKey */

	for(int ii = 1; ii < 10; ii++) {
		encryption[ii].s_box = sub_bytes(encryption[ii].start);
		encryption[ii].s_row = shift_rows(encryption[ii].s_box);
		encryption[ii].m_col = mix_columns(encryption[ii].s_row);
		encryption[ii + 1].start = add_round_key(encryption[ii].m_col, str_to_matrix(round_key_list[ii]));
	}

	/* After Tranformation:
	   * SubBytes
	   * ShiftRows
	   * AddRoundKey */

	encryption[10].s_box = sub_bytes(encryption[10].start);
	encryption[10].s_row = shift_rows(encryption[10].s_box);
	output_ciphertext = add_round_key(encryption[10].s_row, str_to_matrix(round_key_list[10]));

	/* Print Results */

	cout << "************ Encryption ************\n";
	cout << "Question 1: round[1].start: ";
	print_matrix(encryption[1].start);
	cout << "Question 2: round[1].s_box: ";
	print_matrix(encryption[1].s_box);
	cout << "Question 4: round[1].s_row: ";
	print_matrix(encryption[1].s_row);
	cout << "Question 5: round[1].m_col: ";
	print_matrix(encryption[1].m_col);
	cout << "Question 6: round[2].start: ";
	print_matrix(encryption[2].start);
	cout << "Question 7: round[10].start: ";
	print_matrix(encryption[10].start);
	cout << "Question 8: output ciphertext: ";
	print_matrix(output_ciphertext);

	/************************* Decryption ************************/

	/* Initial Transformation:
		* AddRoundKey */

	decryption[1].start = add_round_key(output_ciphertext, str_to_matrix(round_key_list[10]));

	/* Cipher Round:
		* InvShiftRows
		* InvSubBytes
		* AddRoundKey
		* InvMixColumns */

	for(int ii = 1; ii < 10; ii++) {
		int round_key_index = 10 - ii;
		decryption[ii].inv_s_row = inv_shift_rows(decryption[ii].start);
		decryption[ii].inv_s_box = inv_sub_bytes(decryption[ii].inv_s_row);
		decryption[ii].a_key = add_round_key(decryption[ii].inv_s_box, str_to_matrix(round_key_list[round_key_index]));
		decryption[ii + 1].start = inv_mix_columns(decryption[ii].a_key);
	}

	/* After Transformation:
		* InvShiftRows
		* InvSubBytes
		* AddRoundKey */

	decryption[10].inv_s_row = inv_shift_rows(decryption[10].start);
	decryption[10].inv_s_box = inv_sub_bytes(decryption[10].inv_s_row);
	output_plaintext = add_round_key(decryption[10].inv_s_box, str_to_matrix(round_key_list[0]));

	/* Print Results */

	cout << "************ Decryption ************\n";
	cout << "Bonus: output plaintext: ";
	print_matrix(output_plaintext);

	return 0;
}