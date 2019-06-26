

function generate_test(number, name, shares, result) {
    share_code = shares.map(x=>`
        "${x}",`).join('');

    parse_code = shares.map((x,i)=> `
        unsigned short words_${i}[${x.split(' ').length}];
        n = parse_words(shares[${i}], words_${i}, ${x.split(' ').length});`).join('')

    recovery_values = shares.map((x,i) => `words_${i}`).join(', ');
    return `
    void test_vector_${number}(void) {
        char *name = "${name}";
        unsigned int n;
        char *shares[] = {${share_code}		
        };
        char *expected_result = "${result}";
        ${parse_code}
        unsigned short *recovery[] = { ${recovery_values} };
        unsigned char buffer[1024];
        char result[256];

		if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, ${shares.length}, "TREZOR", buffer, 1024);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\\nexpected: '%s'\\ngot:      '%s'\\n\\n", expected_result, result);
        } else {
            printf("pass\\n");
        }   
        }     
    }
    `
}

vectors = require('./vectors.json')


console.log('#include "slip39.h"')

console.log(`
void bufToHex(unsigned char *buf, unsigned int length, char *output, int out_length) {
	for(unsigned int i=0; i<length; 2*i+1<out_length, ++i) {
		sprintf(output + 2*i, "%02x", buf[i]);
	}
}`)

for (number in vectors) {
	[name,shares,result] = vectors[number]
	console.log(generate_test(number,name,shares,result))
}

call_tests = vectors.map((x,i) => `test_vector_${i}();`).join('    \n');
console.log(`
void main(void) {
    setup();
	${call_tests}
}
`)
