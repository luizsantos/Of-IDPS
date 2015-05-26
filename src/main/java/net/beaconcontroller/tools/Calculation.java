/**
 * Sample size reference:
 * - http://www.netquest.com/blog/br/qual-e-o-tamanho-de-amostra-que-preciso/
 * - http://www.publicacoesdeturismo.com.br/calculoamostral/
 * - http://www.surveysystem.com/sscalc.htm
 * - http://www.raosoft.com/samplesize.html
 * - http://www.calculator.net/sample-size-calculator.html
 */
package net.beaconcontroller.tools;

public class Calculation {
    
    /**
     * Determine the necessary sample given a population, using: 
     * - 95% to confidence level (Z);
     * - 05% to margin error.
     * - 50% to proportion of response distribution (unknown);
     * @param N - Population size. 
     * @return - Sample size. 
     */
    public static float sampleSize_cofidence95_error5(int N) {
        float Z= (float) 1.96; // 95%
        float p=(float) 0.5; // 50%
        float e=(float) 0.05; //5%
        return sampleSize(N, Z, p, e);
    }
    
    /**
     * Determine the necessary sample given a population, using: 
     * - 99% to confidence level (Z);
     * - 02% to margin error.
     * - 50% to proportion of response distribution (unknown);
     * @param N - Population size. 
     * @return - Sample size. 
     */
    public static float sampleSize_cofidence99_error2(int N) {
        float Z= (float) 2.575; // 99%
        float p=(float) 0.5; // 50%
        float e=(float) 0.02; //2%
        return sampleSize(N, Z, p, e);
    }
    
    /**
     * Determine the necessary sample given a population.
     * @param N - Population size.
     * @param Z - Confidence level, e.g. 90%->1,645 - 95%->Z=1,96  - 99%->Z=2,575
     * @param p - Proportion of response distribution - If you don't know use 50%->0.5.
     * @param e - Margin error. 
     * @return - Sample size. 
     */
    public static float sampleSize(int N, float Z, float p, float e) {
        float n1,n2;
        float Z2=Z*Z;
        float e2=e*e;
        n1 = N*Z2*p*(1-p);
        n2 = Z2*p*(1-p)+e2*(N-1);
        return n1/n2;
    }
}
