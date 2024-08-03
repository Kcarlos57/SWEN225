package swen225.monopoly;

/**
 * @author carloskhal
 *
 */
public class Station extends Property {
  /**
   * @param name
   * @param price
   */
  public Station(String name, int price) {
    super(name, price);
  }

  /**
   * Calcuate rent for this station. Should only be called if hasOwner() == true.
   */
  public int getRent() {
    // first, determine how many stations owned by player
    int nstations = 0;
    for (Property p : getOwner()) {
      if (p instanceof Station) {
        nstations = nstations + 1;
      }
    }
    // now compute rent, taking number owned into account
    return 50 * nstations;
  }

  /**
   * Override default equals() method.
   */
  public boolean equals(Object o) {
    if (o instanceof Station) {
      return super.equals(o);
    }
    return false;
  }

  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    return result * prime;
  }
}
