#include "slip39.h"

void bufToHex(unsigned char *buf, unsigned int length, char *output, int out_length);
void bufToHex(unsigned char *buf, unsigned int length, char *output, int out_length) {
	for(unsigned int i=0; i<length &&2*i+1<out_length; ++i) {
		sprintf(output + 2*i, "%02x", buf[i]);
	}
}

    void test_vector_0(void);
    void test_vector_0(void) {
        char *name = "1. Valid mnemonic without sharing (128 bits)";
        unsigned int n;
        char *shares[] = {
        "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard",		
        };
        char *expected_result = "bb54aac4b89dc868ba37d9cc21b2cece";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        const unsigned short *recovery[] = { words_0 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 1, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_1(void);
    void test_vector_1(void) {
        char *name = "2. Mnemonic with invalid checksum (128 bits)";
        unsigned int n;
        char *shares[] = {
        "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        const unsigned short *recovery[] = { words_0 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 1, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_2(void);
    void test_vector_2(void) {
        char *name = "3. Mnemonic with invalid padding (128 bits)";
        unsigned int n;
        char *shares[] = {
        "duckling enlarge academic academic email result length solution fridge kidney coal piece deal husband erode duke ajar music cargo fitness",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        const unsigned short *recovery[] = { words_0 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 1, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_3(void);
    void test_vector_3(void) {
        char *name = "4. Basic sharing 2-of-3 (128 bits)";
        unsigned int n;
        char *shares[] = {
        "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed",
        "shadow pistol academic acid actress prayer class unknown daughter sweater depict flip twice unkind craft early superior advocate guest smoking",		
        };
        char *expected_result = "b43ceb7e57a0ea8766221624d01b0864";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        const unsigned short *recovery[] = { words_0, words_1 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 2, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_4(void);
    void test_vector_4(void) {
        char *name = "5. Basic sharing 2-of-3 (128 bits)";
        unsigned int n;
        char *shares[] = {
        "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        const unsigned short *recovery[] = { words_0 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 1, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_5(void);
    void test_vector_5(void) {
        char *name = "6. Mnemonics with different identifiers (128 bits)";
        unsigned int n;
        char *shares[] = {
        "adequate smoking academic acid debut wine petition glen cluster slow rhyme slow simple epidemic rumor junk tracks treat olympic tolerate",
        "adequate stay academic agency agency formal party ting frequent learn upstairs remember smear leaf damage anatomy ladle market hush corner",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        const unsigned short *recovery[] = { words_0, words_1 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 2, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_6(void);
    void test_vector_6(void) {
        char *name = "7. Mnemonics with different iteration exponents (128 bits)";
        unsigned int n;
        char *shares[] = {
        "peasant leaves academic acid desert exact olympic math alive axle trial tackle drug deny decent smear dominant desert bucket remind",
        "peasant leader academic agency cultural blessing percent network envelope medal junk primary human pumps jacket fragment payroll ticket evoke voice",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        const unsigned short *recovery[] = { words_0, words_1 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 2, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_7(void);
    void test_vector_7(void) {
        char *name = "8. Mnemonics with mismatching group thresholds (128 bits)";
        unsigned int n;
        char *shares[] = {
        "liberty category beard echo animal fawn temple briefing math username various wolf aviation fancy visual holy thunder yelp helpful payment",
        "liberty category beard email beyond should fancy romp founder easel pink holy hairy romp loyalty material victim owner toxic custody",
        "liberty category academic easy being hazard crush diminish oral lizard reaction cluster force dilemma deploy force club veteran expect photo",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        unsigned short words_2[20];
        n = parse_words(shares[2], words_2, 20);
        const unsigned short *recovery[] = { words_0, words_1, words_2 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 3, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_8(void);
    void test_vector_8(void) {
        char *name = "9. Mnemonics with mismatching group counts (128 bits)";
        unsigned int n;
        char *shares[] = {
        "average senior academic leaf broken teacher expect surface hour capture obesity desire negative dynamic dominant pistol mineral mailman iris aide",
        "average senior academic agency curious pants blimp spew clothes slice script dress wrap firm shaft regular slavery negative theater roster",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        const unsigned short *recovery[] = { words_0, words_1 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 2, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_9(void);
    void test_vector_9(void) {
        char *name = "10. Mnemonics with greater group threshold than group counts (128 bits)";
        unsigned int n;
        char *shares[] = {
        "music husband acrobat acid artist finance center either graduate swimming object bike medical clothes station aspect spider maiden bulb welcome",
        "music husband acrobat agency advance hunting bike corner density careful material civil evil tactics remind hawk discuss hobo voice rainbow",
        "music husband beard academic black tricycle clock mayor estimate level photo episode exclude ecology papa source amazing salt verify divorce",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        unsigned short words_2[20];
        n = parse_words(shares[2], words_2, 20);
        const unsigned short *recovery[] = { words_0, words_1, words_2 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 3, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_10(void);
    void test_vector_10(void) {
        char *name = "11. Mnemonics with duplicate member indices (128 bits)";
        unsigned int n;
        char *shares[] = {
        "device stay academic always dive coal antenna adult black exceed stadium herald advance soldier busy dryer daughter evaluate minister laser",
        "device stay academic always dwarf afraid robin gravity crunch adjust soul branch walnut coastal dream costume scholar mortgage mountain pumps",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        const unsigned short *recovery[] = { words_0, words_1 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 2, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_11(void);
    void test_vector_11(void) {
        char *name = "12. Mnemonics with mismatching member thresholds (128 bits)";
        unsigned int n;
        char *shares[] = {
        "hour painting academic academic device formal evoke guitar random modern justice filter withdraw trouble identify mailman insect general cover oven",
        "hour painting academic agency artist again daisy capital beaver fiber much enjoy suitable symbolic identify photo editor romp float echo",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        const unsigned short *recovery[] = { words_0, words_1 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 2, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_12(void);
    void test_vector_12(void) {
        char *name = "13. Mnemonics giving an invalid digest (128 bits)";
        unsigned int n;
        char *shares[] = {
        "guilt walnut academic acid deliver remove equip listen vampire tactics nylon rhythm failure husband fatigue alive blind enemy teaspoon rebound",
        "guilt walnut academic agency brave hamster hobo declare herd taste alpha slim criminal mild arcade formal romp branch pink ambition",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        const unsigned short *recovery[] = { words_0, words_1 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 2, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_13(void);
    void test_vector_13(void) {
        char *name = "14. Insufficient number of groups (128 bits, case 1)";
        unsigned int n;
        char *shares[] = {
        "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        const unsigned short *recovery[] = { words_0 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 1, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_14(void);
    void test_vector_14(void) {
        char *name = "15. Insufficient number of groups (128 bits, case 2)";
        unsigned int n;
        char *shares[] = {
        "eraser senior decision scared cargo theory device idea deliver modify curly include pancake both news skin realize vitamins away join",
        "eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        const unsigned short *recovery[] = { words_0, words_1 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 2, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_15(void);
    void test_vector_15(void) {
        char *name = "16. Threshold number of groups, but insufficient number of members in one group (128 bits)";
        unsigned int n;
        char *shares[] = {
        "eraser senior decision shadow artist work morning estate greatest pipeline plan ting petition forget hormone flexible general goat admit surface",
        "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        const unsigned short *recovery[] = { words_0, words_1 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 2, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_16(void);
    void test_vector_16(void) {
        char *name = "17. Threshold number of groups and members in each group (128 bits, case 1)";
        unsigned int n;
        char *shares[] = {
        "eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter",
        "eraser senior ceramic snake clay various huge numb argue hesitate auction category timber browser greatest hanger petition script leaf pickup",
        "eraser senior ceramic shaft dynamic become junior wrist silver peasant force math alto coal amazing segment yelp velvet image paces",
        "eraser senior ceramic round column hawk trust auction smug shame alive greatest sheriff living perfect corner chest sled fumes adequate",
        "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing",		
        };
        char *expected_result = "7c3397a292a5941682d7a4ae2d898d11";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        unsigned short words_2[20];
        n = parse_words(shares[2], words_2, 20);
        unsigned short words_3[20];
        n = parse_words(shares[3], words_3, 20);
        unsigned short words_4[20];
        n = parse_words(shares[4], words_4, 20);
        const unsigned short *recovery[] = { words_0, words_1, words_2, words_3, words_4 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 5, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_17(void);
    void test_vector_17(void) {
        char *name = "18. Threshold number of groups and members in each group (128 bits, case 2)";
        unsigned int n;
        char *shares[] = {
        "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing",
        "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",
        "eraser senior decision scared cargo theory device idea deliver modify curly include pancake both news skin realize vitamins away join",		
        };
        char *expected_result = "7c3397a292a5941682d7a4ae2d898d11";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        unsigned short words_2[20];
        n = parse_words(shares[2], words_2, 20);
        const unsigned short *recovery[] = { words_0, words_1, words_2 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 3, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_18(void);
    void test_vector_18(void) {
        char *name = "19. Threshold number of groups and members in each group (128 bits, case 3)";
        unsigned int n;
        char *shares[] = {
        "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",
        "eraser senior acrobat romp bishop medical gesture pumps secret alive ultimate quarter priest subject class dictate spew material endless market",		
        };
        char *expected_result = "7c3397a292a5941682d7a4ae2d898d11";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        const unsigned short *recovery[] = { words_0, words_1 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 2, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_19(void);
    void test_vector_19(void) {
        char *name = "20. Valid mnemonic without sharing (256 bits)";
        unsigned int n;
        char *shares[] = {
        "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect luck",		
        };
        char *expected_result = "989baf9dcaad5b10ca33dfd8cc75e42477025dce88ae83e75a230086a0e00e92";
        
        unsigned short words_0[33];
        n = parse_words(shares[0], words_0, 33);
        const unsigned short *recovery[] = { words_0 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 1, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_20(void);
    void test_vector_20(void) {
        char *name = "21. Mnemonic with invalid checksum (256 bits)";
        unsigned int n;
        char *shares[] = {
        "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect lunar",		
        };
        char *expected_result = "";
        
        unsigned short words_0[33];
        n = parse_words(shares[0], words_0, 33);
        const unsigned short *recovery[] = { words_0 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 1, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_21(void);
    void test_vector_21(void) {
        char *name = "22. Mnemonic with invalid padding (256 bits)";
        unsigned int n;
        char *shares[] = {
        "theory painting academic academic campus sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips facility obtain sister",		
        };
        char *expected_result = "";
        
        unsigned short words_0[33];
        n = parse_words(shares[0], words_0, 33);
        const unsigned short *recovery[] = { words_0 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 1, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_22(void);
    void test_vector_22(void) {
        char *name = "23. Basic sharing 2-of-3 (256 bits)";
        unsigned int n;
        char *shares[] = {
        "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap",
        "humidity disease academic agency actress jacket gross physics cylinder solution fake mortgage benefit public busy prepare sharp friar change work slow purchase ruler again tricycle involve viral wireless mixture anatomy desert cargo upgrade",		
        };
        char *expected_result = "c938b319067687e990e05e0da0ecce1278f75ff58d9853f19dcaeed5de104aae";
        
        unsigned short words_0[33];
        n = parse_words(shares[0], words_0, 33);
        unsigned short words_1[33];
        n = parse_words(shares[1], words_1, 33);
        const unsigned short *recovery[] = { words_0, words_1 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 2, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_23(void);
    void test_vector_23(void) {
        char *name = "24. Basic sharing 2-of-3 (256 bits)";
        unsigned int n;
        char *shares[] = {
        "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap",		
        };
        char *expected_result = "";
        
        unsigned short words_0[33];
        n = parse_words(shares[0], words_0, 33);
        const unsigned short *recovery[] = { words_0 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 1, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_24(void);
    void test_vector_24(void) {
        char *name = "25. Mnemonics with different identifiers (256 bits)";
        unsigned int n;
        char *shares[] = {
        "smear husband academic acid deadline scene venture distance dive overall parking bracelet elevator justice echo burning oven chest duke nylon",
        "smear isolate academic agency alpha mandate decorate burden recover guard exercise fatal force syndrome fumes thank guest drift dramatic mule",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        const unsigned short *recovery[] = { words_0, words_1 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 2, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_25(void);
    void test_vector_25(void) {
        char *name = "26. Mnemonics with different iteration exponents (256 bits)";
        unsigned int n;
        char *shares[] = {
        "finger trash academic acid average priority dish revenue academic hospital spirit western ocean fact calcium syndrome greatest plan losing dictate",
        "finger traffic academic agency building lilac deny paces subject threaten diploma eclipse window unknown health slim piece dragon focus smirk",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        const unsigned short *recovery[] = { words_0, words_1 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 2, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_26(void);
    void test_vector_26(void) {
        char *name = "27. Mnemonics with mismatching group thresholds (256 bits)";
        unsigned int n;
        char *shares[] = {
        "flavor pink beard echo depart forbid retreat become frost helpful juice unwrap reunion credit math burning spine black capital lair",
        "flavor pink beard email diet teaspoon freshman identify document rebound cricket prune headset loyalty smell emission skin often square rebound",
        "flavor pink academic easy credit cage raisin crazy closet lobe mobile become drink human tactics valuable hand capture sympathy finger",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        unsigned short words_2[20];
        n = parse_words(shares[2], words_2, 20);
        const unsigned short *recovery[] = { words_0, words_1, words_2 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 3, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_27(void);
    void test_vector_27(void) {
        char *name = "28. Mnemonics with mismatching group counts (256 bits)";
        unsigned int n;
        char *shares[] = {
        "column flea academic leaf debut extra surface slow timber husky lawsuit game behavior husky swimming already paper episode tricycle scroll",
        "column flea academic agency blessing garbage party software stadium verify silent umbrella therapy decorate chemical erode dramatic eclipse replace apart",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        const unsigned short *recovery[] = { words_0, words_1 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 2, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_28(void);
    void test_vector_28(void) {
        char *name = "29. Mnemonics with greater group threshold than group counts (256 bits)";
        unsigned int n;
        char *shares[] = {
        "smirk pink acrobat acid auction wireless impulse spine sprinkle fortune clogs elbow guest hush loyalty crush dictate tracks airport talent",
        "smirk pink acrobat agency dwarf emperor ajar organize legs slice harvest plastic dynamic style mobile float bulb health coding credit",
        "smirk pink beard academic alto strategy carve shame language rapids ruin smart location spray training acquire eraser endorse submit peaceful",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        unsigned short words_2[20];
        n = parse_words(shares[2], words_2, 20);
        const unsigned short *recovery[] = { words_0, words_1, words_2 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 3, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_29(void);
    void test_vector_29(void) {
        char *name = "30. Mnemonics with duplicate member indices (256 bits)";
        unsigned int n;
        char *shares[] = {
        "fishing recover academic always device craft trend snapshot gums skin downtown watch device sniff hour clock public maximum garlic born",
        "fishing recover academic always aircraft view software cradle fangs amazing package plastic evaluate intend penalty epidemic anatomy quarter cage apart",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        const unsigned short *recovery[] = { words_0, words_1 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 2, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_30(void);
    void test_vector_30(void) {
        char *name = "31. Mnemonics with mismatching member thresholds (256 bits)";
        unsigned int n;
        char *shares[] = {
        "evoke garden academic academic answer wolf scandal modern warmth station devote emerald market physics surface formal amazing aquatic gesture medical",
        "evoke garden academic agency deal revenue knit reunion decrease magazine flexible company goat repair alarm military facility clogs aide mandate",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        const unsigned short *recovery[] = { words_0, words_1 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 2, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_31(void);
    void test_vector_31(void) {
        char *name = "32. Mnemonics giving an invalid digest (256 bits)";
        unsigned int n;
        char *shares[] = {
        "river deal academic acid average forbid pistol peanut custody bike class aunt hairy merit valid flexible learn ajar very easel",
        "river deal academic agency camera amuse lungs numb isolate display smear piece traffic worthy year patrol crush fact fancy emission",		
        };
        char *expected_result = "";
        
        unsigned short words_0[20];
        n = parse_words(shares[0], words_0, 20);
        unsigned short words_1[20];
        n = parse_words(shares[1], words_1, 20);
        const unsigned short *recovery[] = { words_0, words_1 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 2, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_32(void);
    void test_vector_32(void) {
        char *name = "33. Insufficient number of groups (256 bits, case 1)";
        unsigned int n;
        char *shares[] = {
        "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",		
        };
        char *expected_result = "";
        
        unsigned short words_0[33];
        n = parse_words(shares[0], words_0, 33);
        const unsigned short *recovery[] = { words_0 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 1, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_33(void);
    void test_vector_33(void) {
        char *name = "34. Insufficient number of groups (256 bits, case 2)";
        unsigned int n;
        char *shares[] = {
        "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
        "wildlife deal decision smug ancestor genuine move huge cubic strategy smell game costume extend swimming false desire fake traffic vegan senior twice timber submit leader payroll fraction apart exact forward pulse tidy install",		
        };
        char *expected_result = "";
        
        unsigned short words_0[33];
        n = parse_words(shares[0], words_0, 33);
        unsigned short words_1[33];
        n = parse_words(shares[1], words_1, 33);
        const unsigned short *recovery[] = { words_0, words_1 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 2, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_34(void);
    void test_vector_34(void) {
        char *name = "35. Threshold number of groups, but insufficient number of members in one group (256 bits)";
        unsigned int n;
        char *shares[] = {
        "wildlife deal decision shadow analysis adjust bulb skunk muscle mandate obesity total guitar coal gravity carve slim jacket ruin rebuild ancestor numerous hour mortgage require herd maiden public ceiling pecan pickup shadow club",
        "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",		
        };
        char *expected_result = "";
        
        unsigned short words_0[33];
        n = parse_words(shares[0], words_0, 33);
        unsigned short words_1[33];
        n = parse_words(shares[1], words_1, 33);
        const unsigned short *recovery[] = { words_0, words_1 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 2, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_35(void);
    void test_vector_35(void) {
        char *name = "36. Threshold number of groups and members in each group (256 bits, case 1)";
        unsigned int n;
        char *shares[] = {
        "wildlife deal ceramic round aluminum pitch goat racism employer miracle percent math decision episode dramatic editor lily prospect program scene rebuild display sympathy have single mustang junction relate often chemical society wits estate",
        "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
        "wildlife deal ceramic scatter argue equip vampire together ruin reject literary rival distance aquatic agency teammate rebound false argue miracle stay again blessing peaceful unknown cover beard acid island language debris industry idle",
        "wildlife deal ceramic snake agree voter main lecture axis kitchen physics arcade velvet spine idea scroll promise platform firm sharp patrol divorce ancestor fantasy forbid goat ajar believe swimming cowboy symbolic plastic spelling",
        "wildlife deal decision shadow analysis adjust bulb skunk muscle mandate obesity total guitar coal gravity carve slim jacket ruin rebuild ancestor numerous hour mortgage require herd maiden public ceiling pecan pickup shadow club",		
        };
        char *expected_result = "5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b";
        
        unsigned short words_0[33];
        n = parse_words(shares[0], words_0, 33);
        unsigned short words_1[33];
        n = parse_words(shares[1], words_1, 33);
        unsigned short words_2[33];
        n = parse_words(shares[2], words_2, 33);
        unsigned short words_3[33];
        n = parse_words(shares[3], words_3, 33);
        unsigned short words_4[33];
        n = parse_words(shares[4], words_4, 33);
        const unsigned short *recovery[] = { words_0, words_1, words_2, words_3, words_4 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 5, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_36(void);
    void test_vector_36(void) {
        char *name = "37. Threshold number of groups and members in each group (256 bits, case 2)";
        unsigned int n;
        char *shares[] = {
        "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
        "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",
        "wildlife deal decision smug ancestor genuine move huge cubic strategy smell game costume extend swimming false desire fake traffic vegan senior twice timber submit leader payroll fraction apart exact forward pulse tidy install",		
        };
        char *expected_result = "5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b";
        
        unsigned short words_0[33];
        n = parse_words(shares[0], words_0, 33);
        unsigned short words_1[33];
        n = parse_words(shares[1], words_1, 33);
        unsigned short words_2[33];
        n = parse_words(shares[2], words_2, 33);
        const unsigned short *recovery[] = { words_0, words_1, words_2 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 3, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_37(void);
    void test_vector_37(void) {
        char *name = "38. Threshold number of groups and members in each group (256 bits, case 3)";
        unsigned int n;
        char *shares[] = {
        "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",
        "wildlife deal acrobat romp anxiety axis starting require metric flexible geology game drove editor edge screw helpful have huge holy making pitch unknown carve holiday numb glasses survive already tenant adapt goat fangs",		
        };
        char *expected_result = "5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b";
        
        unsigned short words_0[33];
        n = parse_words(shares[0], words_0, 33);
        unsigned short words_1[33];
        n = parse_words(shares[1], words_1, 33);
        const unsigned short *recovery[] = { words_0, words_1 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 2, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_38(void);
    void test_vector_38(void) {
        char *name = "39. Mnemonic with insufficient length";
        unsigned int n;
        char *shares[] = {
        "junk necklace academic academic acne isolate join hesitate lunar roster dough calcium chemical ladybug amount mobile glasses verify cylinder",		
        };
        char *expected_result = "";
        
        unsigned short words_0[19];
        n = parse_words(shares[0], words_0, 19);
        const unsigned short *recovery[] = { words_0 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 1, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

    void test_vector_39(void);
    void test_vector_39(void) {
        char *name = "40. Mnemonic with invalid master secret length";
        unsigned int n;
        char *shares[] = {
        "fraction necklace academic academic award teammate mouse regular testify coding building member verdict purchase blind camera duration email prepare spirit quarter",		
        };
        char *expected_result = "";
        
        unsigned short words_0[21];
        n = parse_words(shares[0], words_0, 21);
        const unsigned short *recovery[] = { words_0 };
        unsigned char buffer[32];
        char result[256];

		//if( strlen(expected_result) > 0 ) {
			
        printf("%s - ", name);
        int length = combine_mnemonics(recovery, n, 1, "TREZOR", NULL, buffer, 32);

        if(length > 0) {
            bufToHex(buffer, length, result, 256);
        } else {
            result[0] = 0;
        }

        if(strcmp(result,expected_result) != 0) {
            printf("fail\nexpected: '%s'\ngot:      '%s'\n\n", expected_result, result);
        } else {
            printf("pass\n");
        }   
        //}     
    }
    

int main(void) {
	test_vector_0();    
test_vector_1();    
test_vector_2();    
test_vector_3();    
test_vector_4();    
test_vector_5();    
test_vector_6();    
test_vector_7();    
test_vector_8();    
test_vector_9();    
test_vector_10();    
test_vector_11();    
test_vector_12();    
test_vector_13();    
test_vector_14();    
test_vector_15();    
test_vector_16();    
test_vector_17();    
test_vector_18();    
test_vector_19();    
test_vector_20();    
test_vector_21();    
test_vector_22();    
test_vector_23();    
test_vector_24();    
test_vector_25();    
test_vector_26();    
test_vector_27();    
test_vector_28();    
test_vector_29();    
test_vector_30();    
test_vector_31();    
test_vector_32();    
test_vector_33();    
test_vector_34();    
test_vector_35();    
test_vector_36();    
test_vector_37();    
test_vector_38();    
test_vector_39();
    return 0;
}

