/*PLEASE DO NOT EDIT THIS CODE*/
/*This code was generated using the UMPLE 1.32.1.6535.66c005ced modeling language!*/

import java.awt.*;

public class Door implements Cell {

    //------------------------
    // MEMBER VARIABLES
    //------------------------

    //Door Attributes
    private Estate estate;

    //------------------------
    // CONSTRUCTOR
    //------------------------

    public Door(Estate aEstate) {
        super();
        estate = aEstate;
    }

    //------------------------
    // INTERFACE
    //------------------------

    public Estate getEstate() {
        return estate;
    }
    /* Code from template association_GetMany */

    // line 188 "model.ump"
    public String toString() {
        return "Door";
    }


    // line 190 "model.ump"
    public boolean isEntrance() {
        return true;
    }

    @Override
    public boolean isDoor() {
        return true;
    }

    @Override
    public String getDisplayChar() {
        return "D";
    }

    public static class DoorEnteredEvent extends Throwable {
        Estate estate;
        public DoorEnteredEvent(Estate estate) {
            super();
            this.estate = estate;
        }


    }

    @Override
    public Color getColor() {
        return Color.cyan;
    }
}
