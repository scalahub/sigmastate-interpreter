package scapi.sigma

import java.math.BigInteger
import java.security.SecureRandom

import org.bouncycastle.math.ec.ECPoint

import scala.util.Try


/**
  * This is the general interface for the discrete logarithm group.
  * Every class in the DlogGroup family implements this interface.
  *
  *
  * The discrete logarithm problem is as follows: given a generator g of a finite
  * group G and a random element h in G, find the (unique) integer x such that
  * `g^x = h`.
  *
  * In cryptography, we are interested in groups for which the discrete logarithm problem
  * (Dlog for short) is assumed to be hard. The most known groups of that kind are some Elliptic curve groups.
  *
  * Another issue pertaining elliptic curves is the need to find a suitable mapping that will convert an arbitrary
  * message (that is some binary string) to an element of the group and vice-versa.
  *
  * Only a subset of the messages can be effectively mapped to a group element in such a way that there is a one-to-one
  * injection that converts the string to a group element and vice-versa.
  *
  * On the other hand, any group element can be mapped to some string.
  *
  * In this case, the operation is not invertible. This functionality is implemented by the functions:
  *  - {@code encodeByteArrayToGroupElement(binaryString: Array[Byte]): ElemType}
  *  - {@code decodeGroupElementToByteArray(element: ElemType) : Array[Byte]}
  *  - {@code mapAnyGroupElementToByteArray(element: ElemType): Array[Byte]}
  *
  *  The first two work as a pair and decodeGroupElementToByteArray is the inverse of encodeByteArrayToGroupElement,
  *  whereas the last one works alone and does not have an inverse.
  *
  *  @tparam ElemType is concrete type
  */
trait DlogGroup[ElemType <: ECPoint] {

  val random = new SecureRandom()

  /**
    * The generator g of the group is an element of the group such that, when written multiplicatively, every element of the group is a power of g.
    * @return the generator of this Dlog group
    */
  def generator: ElemType

  /**
    *
    * @return the order of this Dlog group
    */
  def order: BigInteger


  /**
    *
    * @return the identity of this Dlog group
    */
  def identity: ElemType

  /**
    * Checks if the given element is a member of this Dlog group
    * @param element possible group element for which to check that it is a member of this group
    * @return <code>true</code> if the given element is a member of this group;<p>
    * 		   <code>false</code> otherwise.
    */
  def isMember(element: ElemType): Boolean

  /**
    * Checks if the order of this group is greater than `2^numBits`
    * @param numBits
    * @return <code>true</code> if the order is greater than `2^numBits`;<p>
    * 		   <code>false</code> otherwise.
    */
  def orderGreaterThan(numBits: Int): Boolean

  /**
    * Calculates the inverse of the given GroupElement.
    * @param groupElement to invert
    * @return the inverse element of the given GroupElement
    * @throws IllegalArgumentException
    **/
  def getInverse(groupElement: ElemType): ElemType

  /**
    * Raises the base GroupElement to the exponent. The result is another GroupElement.
    * @param exponent
    * @param base
    * @return the result of the exponentiation
    * @throws IllegalArgumentException
    */
  def exponentiate(base: ElemType, exponent: BigInteger): ElemType

  /**
    * Multiplies two GroupElements
    * @param groupElement1
    * @param groupElement2
    * @return the multiplication result
    * @throws IllegalArgumentException
    */
  def multiplyGroupElements(groupElement1: ElemType, groupElement2: ElemType): ElemType

  /**
    * Creates a random member of this Dlog group
    * @return the random element
    */
  def createRandomElement(): ElemType

  /**
    * Creates a random generator of this Dlog group
    *
    * @return the random generator
    */
  def createRandomGenerator(): ElemType = {
    // in prime order groups every element except the identity is a generator.
    // get a random element in the group
    var randGen = createRandomElement()

    // if the given element is the identity, get a new random element
    while ( {
      randGen.isInfinity
    }) randGen = createRandomElement()

    randGen
  }

  /**
    * Reconstructs a GroupElement given the GroupElementSendableData data, which might have been received through a Channel open between the party holding this DlogGroup and
    * some other party.
    * @param bCheckMembership whether to check that the data provided can actually reconstruct an element of this DlogGroup. Since this action is expensive it should be used only if necessary.
    * @param data the GroupElementSendableData from which we wish to "reconstruct" an element of this DlogGroup
    * @return the reconstructed GroupElement
    */
  def reconstructElement(bCheckMembership: Boolean, data: GroupAgnosticEcElement): Try[ElemType]

  /**
    * Computes the product of several exponentiations with distinct bases
    * and distinct exponents.
    * Instead of computing each part separately, an optimization is used to
    * compute it simultaneously.
    * @param groupElements
    * @param exponentiations
    * @return the exponentiation result
    */
  def simultaneousMultipleExponentiations(groupElements: Array[ElemType], exponentiations: Array[BigInteger]): ElemType

  /**
    * Computes the product of several exponentiations of the same base
    * and distinct exponents.
    * An optimization is used to compute it more quickly by keeping in memory
    * the result of h1, h2, h4,h8,... and using it in the calculation.<p>
    * Note that if we want a one-time exponentiation of h it is preferable to use the basic exponentiation function
    * since there is no point to keep anything in memory if we have no intention to use it.
    * @param base
    * @param exponent
    * @return the exponentiation result
    */
  def exponentiateWithPreComputedValues(base: ElemType, exponent: BigInteger): ElemType

  /**
    * This function cleans up any resources used by exponentiateWithPreComputedValues for the requested base.
    * It is recommended to call it whenever an application does not need to continue calculating exponentiations for this specific base.
    *
    * @param base
    */
  def endExponentiateWithPreComputedValues(base: ElemType)

  /**
    * This function takes any string of length up to k bytes and encodes it to a Group Element.
    * k can be obtained by calling getMaxLengthOfByteArrayForEncoding() and it is calculated upon
    * construction of this group; it depends on the length in bits of p.<p>
    * The encoding-decoding functionality is not a bijection, that is, it is a 1-1 function
    * but is not onto.
    * Therefore, any string of length in bytes up to k can be encoded to a group element
    * but not every group element can be decoded to a binary string in the group of binary strings
    * of length up to `2^k`.<p>
    * Thus, the right way to use this functionality is first to encode a byte array and then to
    * decode it, and not the opposite.
    *
    * @param binaryString the byte array to encode
    * @return the encoded group Element <B> or null </B>if element could not be encoded
    */
  def encodeByteArrayToGroupElement(binaryString: Array[Byte]): Try[ElemType]

  /**
    * This function decodes a group element to a byte array. This function is guaranteed
    * to work properly ONLY if the group element was obtained as a result of
    * encoding a binary string of length in bytes up to k.<p>
    * This is because the encoding-decoding functionality is not a bijection, that is, it is a 1-1 function but is not onto.
    * Therefore, any string of length in bytes up to k can be encoded to a group element but not any group element can be decoded
    * to a binary sting in the group of binary strings of length up to `2^k`.
    *
    * @param groupElement the element to decode
    * @return the decoded byte array
    */
  def decodeGroupElementToByteArray(groupElement: ElemType): Array[Byte]


  /**
    * This function returns the value <I>k</I> which is the maximum length of a string to be encoded to a Group Element of this group.<p>
    * Any string of length <I>k</I> has a numeric value that is less than (p-1)/2 - 1.
    * <I>k</I> is the maximum length a binary string is allowed to be in order to encode the said binary string to a group element and vice-versa.<p>
    * If a string exceeds the <I>k</I> length it cannot be encoded.
    * @return k the maximum length of a string to be encoded to a Group Element of this group. k can be zero if there is no maximum.
    */
  def maxLengthOfByteArrayForEncoding: Int

  /**
    * This function maps a group element of this dlog group to a byte array.<p>
    * This function does not have an inverse function, that is, it is not possible to re-construct the original group element from the resulting byte array.
    * @return a byte array representation of the given group element
    */
  def mapAnyGroupElementToByteArray(groupElement: ElemType): Array[Byte]
}
