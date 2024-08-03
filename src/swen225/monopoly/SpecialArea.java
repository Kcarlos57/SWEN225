package swen225.monopoly;

/**
 * @author carloskhal
 *
 */
public class SpecialArea extends Location {
  /**
   * @param n
   */
  public SpecialArea(String n) {
    super(n);
  }

  public boolean hasOwner() {
    return false;
  }

  /**
   * Should not be called on Special Area
   * @return exception
   */
  public Player getOwner() {
    throw new RuntimeException("Should not call getOwner() on a SpeciaArea!");
  }

  /**
   * Should not be called on Special Area
   * @return exception
   */
  public int getRent() {
    throw new RuntimeException("Should not call getRent() on a SpeciaArea!");
  }

  /**
   * Override default equals() method.
   */
  public boolean equals(Object o) {
    if (o instanceof SpecialArea) {
      return super.equals(o);
    }
    return false;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    return prime * result + getClass().hashCode();
  }

}
