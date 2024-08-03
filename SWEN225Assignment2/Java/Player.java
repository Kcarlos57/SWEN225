import java.util.ArrayList;
import java.util.List;

public class Player {

  //------------------------
  // MEMBER VARIABLES
  //------------------------

  //Player Attributes
  private final String name;
  private boolean hasGuessed = false;
  private List<Card> cards;

  int[] position = new int[2]; // x,y
  int[] prevPosition = new int[2]; // x,y

  //------------------------
  // CONSTRUCTOR
  //------------------------

  public Player(String aName)
  {
    name = aName;
    cards = new ArrayList<Card>();
  }

  //------------------------
  // INTERFACE
  //------------------------

  public boolean setHasGuessed(boolean aHasGuessed)
  {
    boolean wasSet = false;
    hasGuessed = aHasGuessed;
    wasSet = true;
    return wasSet;
  }


  /**
   * Move the player by (x,y)
   * Sets the prevPosition to what the player what at previously
   * @param x
   * @param y
   * @return
   */
  public boolean setPositionWithOffset(int x, int y){
    boolean wasSet = false;
    prevPosition = position;

    int[] newPosition = new int[2];
    newPosition[0] = position[0] + x;
    newPosition[1] = position[1] + y;

    position = newPosition;
    wasSet = true;
    return wasSet;
  }

  /**
   * Set the players positions
   * Used when player selects to move there
   * @param row
   * @param col
   * @return
   */
  public boolean setPositionTo(int row, int col){
    boolean wasSet = false;
    prevPosition = position;
    int[] newPos = new int[2];
    newPos[0] = col;
    newPos[1] = row;
    position = newPos;
    wasSet = true;
    return wasSet;
  }

  /**
   * Sets prevPosition AND position to the same coords
   * Used only for setting up the game
   * @param x
   * @param y
   * @return
   */
  public Player setStartPosition(int x, int y){
    prevPosition[0] = x;
    prevPosition[1] = y;
    position = prevPosition;
    return this;
  }

  public void addCard(Card card)
  {
    cards.add(card);
  }

  public String getName()
  {
    return name;
  }

  public boolean getHasGuessed()
  {
    return hasGuessed;
  }

  public List<Card> getCards()
  {
    return cards;
  }

  public String toString()
  {
    return ConsoleCommands.inYellow(this.name) + System.getProperties().getProperty("line.separator") +
            "  " + "Your Cards" + "=" + getCards().toString() + System.getProperties().getProperty("line.separator");
  }

  public int[] getPosition(){
    return position;
  }
}
