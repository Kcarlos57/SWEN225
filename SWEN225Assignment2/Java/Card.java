public class Card
{

  //------------------------
  // MEMBER VARIABLES
  //------------------------

  //Card Attributes
  enum CardType{Character, Weapon, Estate}
  CardType cardType;
  private final String cardName;

  //------------------------
  // CONSTRUCTOR
  //------------------------

  public Card(CardType aCardType, String aCardName)
  {
    cardType = aCardType;
    cardName = aCardName;
  }

  //------------------------
  // INTERFACE
  //------------------------

  public CardType getCardType()
  {
    return cardType;
  }
  public String getCardName()
  {
    return cardName;
  }


  /**
   * Returns if cards are equal
   */
   public boolean equals(Card other){
     if(other==null)throw new NullPointerException("The other card is null");

     return this.cardName.equals(other.cardName);
   }


  public String toString()
  {
    return this.getCardType() + ": " + this.getCardName();
  }
}
