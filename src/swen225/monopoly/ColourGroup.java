package swen225.monopoly;

import java.util.ArrayList;

/**
 * Group of colours for properties.
 *
 * @author djp
 */

public class ColourGroup {
  private ArrayList<Street> streets = new ArrayList<Street>();
  private String colour;

  /**
   * Create colour group made up of Streets supplied as arguments.
   * @param colour
   * @param streets
   */
  public ColourGroup(String colour, Street... streets) {
    for (Street street : streets) {
      this.streets.add(street);
      street.setColourGroup(this);
    }
    this.colour = colour;
  }

  /**
   * @return color
   */
  public String getColour() {
    return colour;
  }
}
