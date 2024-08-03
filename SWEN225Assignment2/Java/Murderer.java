import java.util.*;
public class Murderer
{
  private final Card weapon ;
  private final Card estate ;
  private final Card person ;

  //------------------------
  // CONSTRUCTOR
  //------------------------

  public Murderer(Card _weapon, Card _estate, Card _person)
  {
    this.weapon = _weapon;
    this.estate = _estate;
    this.person = _person;
  }

  /**
   * Returns if the given cards are the murder ones
   */
  public boolean checkMurderer(Card _weapon, Card _estate, Card _person){
    return this.weapon.equals(_weapon)  && this.estate.equals(_estate) && this.person.equals(_person);
  }

  /**
   * Get the murder cards
   * @return
   */
  public Collection<Card> getCards(){
    return List.of(weapon,estate,person);
  }


  /**
   * Formatted display output
   */
  public String toString(){
    return person.getCardName() + " killed in the " + estate.getCardName() + " with the " + weapon.getCardName();
  }
}
