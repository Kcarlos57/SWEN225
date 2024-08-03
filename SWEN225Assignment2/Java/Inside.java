/*PLEASE DO NOT EDIT THIS CODE*/
/*This code was generated using the UMPLE 1.32.1.6535.66c005ced modeling language!*/


import java.awt.*;

// line 169 "model.ump"
// line 254 "model.ump"
public class Inside implements Cell {

    //------------------------
    // MEMBER VARIABLES
    //------------------------
    private int row;
    private int col;

    //------------------------
    // CONSTRUCTOR
    //------------------------

    public Inside() {
        super();
    }

    public Inside(int row, int col) {
        super();
        this.row = row;
        this.col = col;
    }

    //------------------------
    // INTERFACE
    //------------------------

    public void delete() {
        Cell.super.delete();
    }

    // line 174 "model.ump"
    public String toString() {
        return "Inside";
    }


    // line 176 "model.ump"
    public boolean isWalkable() {
        return false;
    }

    @Override
    public String getDisplayChar() {
        return "I";
    }

    public int getRow() {
    	return row;
    }

    public int getCol() {
    	return col;
    }

    @Override
    public Color getColor() {
        return Color.BLUE;
    }
}