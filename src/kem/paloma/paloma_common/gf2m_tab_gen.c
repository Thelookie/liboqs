/*
 * Copyright (c) 2024 FDL(Future cryptography Design Lab.) Kookmin University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "gf2m_tab_gen.h"
#include <stdint.h>

/**
 * @brief print all table
 *
 * @param [in] gf2m_tables tables for efficient arithmetic over GF(2^13).
 */
void gf2m_print_all_tabs(IN const gf2m_tab* gf2m_tables)
{
    gf2m_print_mul_tab(gf2m_tables);
    gf2m_print_squ_tab(gf2m_tables->squ_tab);
    gf2m_print_sqrt_tab(gf2m_tables->sqrt_tab);
    gf2m_print_inv_tab(gf2m_tables->inv_tab);
}

/**
 * @brief generate precomputation table
 *
 * @param [out] gf2m_tables tables for efficient arithmetic over GF(2^13).
 */
void gf2m_gen_all_tabs(OUT gf2m_tab* gf2m_tables)
{
    gf2m_gen_mul_tab(gf2m_tables);
    gf2m_gen_squ_tab(gf2m_tables->squ_tab);
    gf2m_gen_sqrt_tab(gf2m_tables->sqrt_tab);
    gf2m_gen_inv_tab(gf2m_tables->inv_tab);
}

/**
 * @brief generate gf2m multiplication table
 *
 * @param [out] gf2m_tables tables for efficient arithmetic over GF(2^13).
 */
void gf2m_gen_mul_tab(OUT gf2m_tab* gf2m_tables)
{
    gf2m A1_z7, B1_z7;

    for (gf2m i = 0; i < (1 << GF2M_SPLIT_L); i++)
    {
        for (gf2m j = 0; j < (1 << GF2M_SPLIT_L); j++)
        {
            gf2m_tables->mul00_tab[i][j] = gf2m_mul(i, j); // lower 7bit

            if ((i < (1 << GF2M_SPLIT_H)) && (j < (1 << GF2M_SPLIT_H)))
            {
                A1_z7 = (i << GF2M_SPLIT_L); // times z^7
                B1_z7 = (j << GF2M_SPLIT_L); // times z^7

                // upper 6bit
                gf2m_tables->mul11_tab[i][j] = gf2m_mul(A1_z7, B1_z7); 
            }

            if (i < (1 << GF2M_SPLIT_H))
            {
                A1_z7 = (i << GF2M_SPLIT_L); // times z^7
                
                // upper 6bit x lower 7bit
                gf2m_tables->mul10_tab[i][j] = gf2m_mul(A1_z7, j); 
            }
        }
    }
}

/**
 * @brief generate gf2m square table
 *
 * @param [out] gf2m_tables tables for efficient arithmetic over GF(2^13).
 */
void gf2m_gen_squ_tab(OUT gf2m* squ_tab)
{
    for (gf2m i = 0; i < GF2M_SIZE; i++)
    {
        squ_tab[i] = gf2m_squ(i);
    }
}

/**
 * @brief generate gf2m square root table
 *
 * @param [out] gf2m_tables tables for efficient arithmetic over GF(2^13).
 */
void gf2m_gen_sqrt_tab(OUT gf2m* sqrt_tab)
{
    for (gf2m i = 0; i < GF2M_SIZE; i++)
    {
        sqrt_tab[i] = gf2m_sqrt(i);
    }
}

/**
 * @brief generate gf2m inverse table
 *
 * @param [out] gf2m_tables tables for efficient arithmetic over GF(2^13).
 */
void gf2m_gen_inv_tab(OUT gf2m* inv_tab)
{
    for (gf2m i = 0; i < GF2M_SIZE; i++)
    {
        inv_tab[i] = gf2m_inv(i);
    }
}

/**
 * @brief print mul table
 *
 * @param [in] gf2m_tables tables for efficient arithmetic over GF(2^13).
 */
void gf2m_print_mul_tab(IN const gf2m_tab* gf2m_tables)
{
    printf("GF2M MUL TABLE ={ ");

    int count = 0;

    for (gf2m i = 0; i < (1 << GF2M_SPLIT_H); i++)
    {
        printf("{");
        for (gf2m j = 0; j < (1 << GF2M_SPLIT_H); j++)
        {
            printf("0x%04x", gf2m_tables->mul11_tab[i][j]);
            if (j != GF2M_SPLIT_MASK_H_BIT)
                printf(", ");
            count++;
            if ((count % 20) == 0)
                printf("\n      ");
        }
        printf("}");
        if (i != GF2M_SPLIT_MASK_H_BIT)
            printf(",");
    }
    printf("\n");
    printf("\nnext\n");
    
    count = 0;
    for (gf2m i = 0; i < (1 << GF2M_SPLIT_H); i++)
    {
        printf("{");
        for (gf2m j = 0; j < (1 << GF2M_SPLIT_L); j++)
        {
            printf("0x%04x", gf2m_tables->mul10_tab[i][j]);
            if (j != GF2M_SPLIT_MASK_L_BIT)
                printf(", ");
            count++;
            if ((count % 20) == 0)
                printf("\n      ");
        }
        printf("}");
        if (i != GF2M_SPLIT_MASK_H_BIT)
            printf(",");
    }
    printf("\n");
    printf("\n next \n");

    count = 0;
    for (gf2m i = 0; i < (1 << GF2M_SPLIT_L); i++)
    {
        printf("{");
        for (gf2m j = 0; j < (1 << GF2M_SPLIT_L); j++)
        {
            printf("0x%04x", gf2m_tables->mul00_tab[i][j]);
            if (j != GF2M_SPLIT_MASK_L_BIT)
                printf(", ");
            count++;
            if ((count % 20) == 0)
                printf("\n      ");
        }
        printf("}");
        if (i != GF2M_SPLIT_MASK_L_BIT)
            printf(",");
    }
    printf("};\n");
}

/**
 * @brief print square table
 *
 * @param [in] gf2m_tables tables for efficient arithmetic over GF(2^13).
 */
void gf2m_print_squ_tab(IN const gf2m* squ_tab)
{
    printf("GF2M SQU TABLE = {");

    for (gf2m j = 0; j < GF2M_SIZE; j++)
    {
        printf("0x%04x", squ_tab[j]);
        if (j != 0x1FFF)
            printf(", ");
        if ((j + 1) % 20 == 0)
            printf("\n      ");
    }
    printf("};\n");
}

/**
 * @brief print sqrt table
 *
 * @param [in] gf2m_tables tables for efficient arithmetic over GF(2^13).
 */
void gf2m_print_sqrt_tab(IN const gf2m* sqrt_tab)
{
    printf("gf2m sqrt_tab = {");

    for (gf2m j = 0; j < GF2M_SIZE; j++)
    {
        printf("0x%04x", sqrt_tab[j]);
        if (j != 0x1FFF)
            printf(", ");
        if ((j + 1) % 20 == 0)
            printf("\n      ");
    }
    printf("};\n");
}

/**
 * @brief print inv table
 *
 * @param [in] gf2m_tables tables for efficient arithmetic over GF(2^13).
 */
void gf2m_print_inv_tab(IN const gf2m* inv_tab)
{
    printf("gf2m inv_tab [(1<<GF2M_DEG)] = {");

    for (gf2m j = 0; j < GF2M_SIZE; j++)
    {
        printf("0x%04x", inv_tab[j]);
        if (j != 0x1FFF)
            printf(", ");
        if ((j + 1) % 20 == 0)
            printf("\n      ");
    }
    printf("};\n");
}

/**
 * @brief gf2m table verification
 *
 * @param [in] gf2m_tables tables for efficient arithmetic over GF(2^13).
 */
void gf2m_tab_verify_check(IN const gf2m_tab* gf2m_tables)
{
    int count = 1000000;
    srand(0x46444c);

    /**************  Multiplication  **************/
    gf2m finite_a, finite_b;
    finite_a = rand() % 0x1FFF;
    finite_b = rand() % 0x1FFF;
    gf2m finite_c = finite_a;

    for (int i = 0; i <= count; i++)
    {
        finite_a = gf2m_mul(finite_a, finite_b);
        finite_c = gf2m_mul_w_tab(finite_c, finite_b, gf2m_tables);
        if (finite_a != finite_c)
            printf("error!!\n");
    }
    printf("Multiplication Check\n");

    /**************  Square  **************/
    finite_a = rand() % 0x1FFF;
    finite_c = finite_a;

    for (int i = 0; i <= count; i++)
    {
        finite_a = gf2m_squ(finite_a);
        finite_c = gf2m_squ_w_tab(finite_c, gf2m_tables->squ_tab);
        if (finite_a != finite_c)
            printf("error!!\n");
    }
    printf("Square check \n");

    /**************  Square root  **************/
    finite_a = rand() % 0x1FFF;
    finite_c = finite_a;

    for (int i = 0; i <= count; i++)
    {
        finite_a = gf2m_sqrt(finite_a);
        finite_c = gf2m_sqrt_w_tab(finite_c, gf2m_tables->sqrt_tab);
        if (finite_a != finite_c)
            printf("error!!\n");
    }
    printf("Square root check \n");

    /**************  Inverse  **************/
    finite_a = rand() % 0x1FFF;
    finite_c = finite_a;

    for (int i = 0; i <= count; i++)
    {
        finite_a = gf2m_inv(finite_a);
        finite_c = gf2m_inv_w_tab(finite_c, gf2m_tables->inv_tab);
        if (finite_a != finite_c)
            printf("error!!\n");
    }
    printf("Inverse check \n");
}