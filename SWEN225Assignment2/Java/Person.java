import java.awt.*;

public class Person implements Cell {

  //------------------------
  // MEMBER VARIABLES
  //------------------------
    private final String name;
    private final Player player;

  //------------------------
  // CONSTRUCTOR
  //------------------------

  public Person(Player player)
  {
    super();
    name = player.getName();
    this.player = player;
  }

  //------------------------
  // INTERFACE
  //------------------------

  public void delete()
  {
    Cell.super.delete();
  }

  // line 199 "model.ump"
   public String toString(){
    return "Person";
  }

    // line 201 "model.ump"
   public boolean isWalkable(){
        return false;
    }

    @Override
    public String getDisplayChar() {
      return name.substring(0, 1);
    }

    @Override
    public Color getColor() {
      return Game.getGameInstance().getCurrentPlayer().equals(this.player)? Color.GREEN : Color.RED;
    }

    public Player getPlayer() {
        return player;
    }

    public int getX() {
        return player.position[0];
    }

    public int getY() {
        return player.position[1];
    }

    public int getPrevX() {
        return player.prevPosition[0];
    }

    public int getPrevY() {
        return player.prevPosition[1];
    }
}
