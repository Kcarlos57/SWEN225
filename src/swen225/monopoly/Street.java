package swen225.monopoly;

/**
 * @author carloskhal
 *
 */
public class Street extends Property {
  private int numHouses;
  private int numHotels;
  private int rent; // in $
  private ColourGroup colourGroup;

  /**
   * @param name
   * @param price
   * @param rent
   */
  public Street(String name, int price, int rent) {
    super(name, price);
    this.rent = rent;
    colourGroup = null;
  }

  /**
   * @param group
   */
  public void setColourGroup(ColourGroup group) {
    colourGroup = group;
  }

  /**
   * Get colour group to which this street belongs. Will return null if
   * setColourGroup not already called.
   * @return colourGroup
   */
  public ColourGroup getColourGroup() {
    return colourGroup;
  }

  public int getRent() {
    return rent;
  }

  /**
   * @return numHouses
   */
  public int getHouses() {
    return numHouses;
  }

  /**
   * @return numHotels
   */
  public int getHotels() {
    return numHotels;
  }

  /**
   * Override default equals() method.
   */
  public boolean equals(Object o) {
    if (o instanceof Street) {
      return super.equals(o);
    }
    return false;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + numHouses;
    result = prime * result + numHotels;
    result = prime * result + rent;
    result = prime * result + ((colourGroup == null) ? 0 : colourGroup.hashCode());
    return result;
  }
}
