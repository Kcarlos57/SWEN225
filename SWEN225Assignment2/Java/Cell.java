/*PLEASE DO NOT EDIT THIS CODE*/
/*This code was generated using the UMPLE 1.32.1.6535.66c005ced modeling language!*/


import javax.swing.*;
import java.awt.*;

// line 156 "model.ump"
// line 249 "model.ump"
interface Cell {
    //------------------------
    // INTERFACE
    //------------------------

    default void delete() {
    }

    //------------------------
    // DEVELOPER CODE - PROVIDED AS-IS
    //------------------------

    // line 161 "model.ump"
    default boolean isWalkable() {
        return true;
    }

    // line 164 "model.ump"
    default boolean isDoor() {
        return false;
    }

    default String getDisplayChar() {
        return "_";
    }

    default Color getColor(){ return Color.white;}
}