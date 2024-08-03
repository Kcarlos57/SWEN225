import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import javax.swing.JPanel;

public class GameController implements KeyListener, MouseListener {
    private static GameController instance;

    /**
     * Private constructor for initializing the GameController.
     */
    private GameController() {
        System.out.println("GameController created");
    }

    /**
     * Retrieves the singleton instance of the GameController class.
     *
     * @return The singleton instance of the GameController class.
     */
    public static GameController getController() {
        if (instance == null) {
            instance = new GameController();
        }
        return instance;
    }

    /**
     * Handles the logic when the "End Turn" button is clicked.
     */
    public static void endTurnClicked() {
        System.out.println("End turn clicked");
        Game.getGameInstance().nextPlayerTurn();
        Game.getGameInstance().setGameState(Game.GameState.PlayerToMove);
        Game.getGameInstance().resetPlayerGuessed();

        updateView();
    }

    /**
     * Performs actions when a key is pressed.
     *
     * @param e The KeyEvent object representing the key press event.
     */
    public void keyPressed(KeyEvent e) {
        System.out.println("Key pressed: " + e.getKeyCode());
        if (e.isControlDown() && e.getKeyCode() == KeyEvent.VK_N) {
            createNewGame();
        } else if(e.isControlDown() && e.getKeyCode() == KeyEvent.VK_Q) {
            GameView.getView().confirmQuit();
        } else if(e.isControlDown() && e.getKeyCode() == KeyEvent.VK_G) {
            GameView view = GameView.getView();
            Game game = view.getGame();

            if(game.getState() == Game.GameState.PlayerCanGuessAndSolve) {
                guessButtonClicked();
            }
        } else if(e.isControlDown() && e.getKeyCode() == KeyEvent.VK_S) {
            GameView view = GameView.getView();
            Game game = view.getGame();

            if(game.getState() == Game.GameState.PlayerCanGuessAndSolve || game.getState() == Game.GameState.PlayerCanSolve) {
                solveButtonClicked();
            }
        }
    }

    /**
     * Invoked when a key is typed.
     *
     * @param e The KeyEvent object representing the key typed event.
     */
    public void keyTyped(KeyEvent e) {}

    /**
     * Invoked when a key is released.
     *
     * @param e The KeyEvent object representing the key release event.
     */
    public void keyReleased(KeyEvent e) {}



    /**
     * Performs dice roll.
     * Stored in field in model (Game)
     * Then updates the view based on new state
     */
    public static void rollDice() {
        System.out.println("Dice rolled");
        Game.getGameInstance().performDiceRoll();
        Game.getGameInstance().setGameState(Game.GameState.WaitingForPlayerToMove);
        updateView();
    }

    /**
     * Handles the logic when the "Guess" button is clicked.
     */
    public static void guessButtonClicked() {
        System.out.println("Player guessed");
        Game.getGameInstance().currentPlayerGuessed();

        Solve_GuessAttempts gAttempt = new Solve_GuessAttempts();
        gAttempt.TryGuess(Game.getGameInstance().currentPlayerInEstate().get().name,Game.getGameInstance().getCurrentPlayer());

        // Temporarily adds a guess to the info area
        GameView.getView().updateInfo("Player guessed");
        // and just testing the context buttons
        GameView.getView().setContextButtons("roll");
    }

    /**
     * Handles the logic when the "Solve" button is clicked.
     */
    public static void solveButtonClicked() {
        System.out.println("Solve Button");

        Solve_GuessAttempts gAttempt = new Solve_GuessAttempts();
        gAttempt.TrySolve(Game.getGameInstance().getCurrentPlayer());

        // Temporarily adds a solve to the info area
        GameView.getView().updateInfo("Player solved");
        // and just testing the context buttons
        GameView.getView().setContextButtons("roll");
    }

    /**
     * Handles the logic for creating a new game.
     */
    public static void createNewGame() {
        System.out.println("New Game");
        Game.getGameInstance().resetGame();
        updateView();
    }

    /**
     * Handles the logic for quitting the game.
     * Prints Quit Game and then exits.
     */
    public static void quitGame() {
        System.out.println("Quit Game");
        System.exit(0);
    }

    /**
     * Method called when cell on GUI's board is clicked
     * Row/col are where u clicked
     * @param row
     * @param col
     */
    public static void cellClicked(int row, int col) {
        switch (Game.getState()){
            case WaitingForPlayerToMove -> {
                boolean canMoveThere = Game.getGameInstance().getBoard().isMoveValidAtClick(row,col);
                if(!canMoveThere) {
                    GameView.getView().updateInfo("Can't move there!");
                    return;
                }
                try {
                    Game.getGameInstance().moveCurrentPlayerTo(row,col);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }

                Optional<Estate> inEstate = Game.getGameInstance().currentPlayerInEstate();
                if(inEstate.isPresent()){
                    Game.getGameInstance().setGameState(Game.GameState.PlayerCanGuessAndSolve);
                    System.out.println("You are in " + inEstate.get().name);
                }
                else{
                    Game.getGameInstance().setGameState(Game.GameState.PlayerCanSolve);
                    System.out.println("Not in an estate!");
                }

                GameView.getView().repaintBoard();
                updateView();
            }
            default -> {
                GameView.getView().updateInfo("Not time to move!! (wrong state)");
            }
        }
    }

    /**
     * shortcuts
     */

    /**
     * Update the GUI's view based on the gameState
     */
    public static void updateView(){
        GameView view = GameView.getView();

        switch (Game.getState()){
            case PlayerToMove -> {
                view.repaintBoard();
                view.updateInfo("Player To move..");
                view.setContextButtons("roll");
                updateToCurrentPlayer();
            }
            case WaitingForPlayerToMove -> {
                int[] maxMoves = Game.getGameInstance().getCurrentMaxMoves();
                view.updateInfo("You rolled a " + maxMoves[0] + " and a " + maxMoves[1]);
                view.setContextButtons(); // get rid of all buttons
                updateToCurrentPlayer();
            }
            case GameSetup -> {
                view.updateInfo("Game setting up...");
                view.setContextButtons();
                view.displaySetup();
                Game.getGameInstance().resetPlayerGuessed();
            }
            case PlayerWon -> {
                view.updateInfo("Player has won!");
                view.setContextButtons("new game","quit");
            }
            case PlayersLost -> {
                // TODO: Change to this state when EVERYONE loses
                view.updateInfo("You all lost!!");
                view.setContextButtons("new game","quit");
            }
            case PlayerCanGuessAndSolve -> {
                view.updateInfo("You can solve/guess nowww..");
                view.setContextButtons("guess","solve","end turn");
            }
            case PlayerCanSolve -> {
                view.updateInfo("You can solve nowww..");
                view.setContextButtons("solve","end turn");
            }
            default -> throw new IllegalStateException("This shouldn't happen!");
        }
    }

    /**
     * Updates the GUI to display the current player's information.
     */
    private static void updateToCurrentPlayer(){
        String name = Game.getGameInstance().getCurrentPlayer().getName();
        GameView.getView().setBoardTitle("It is " + name + "'s turn");

        // Update the player's cards
        List<Card> playersCards = Game.getGameInstance().getCurrentPlayer().getCards();
        GameView.getView().showPlayersCards(playersCards);
    }

    /**
     * Method called by player num radio buttons
     * Sets up players (final step in game setup)
     * Set gamestate to PlayerToMove
     * @param i
     */
    public static void setupPlayers(int i) {
        System.out.println("Creating game with " + i + " players...");
        Game.getGameInstance().setupPlayers(i);
        Game.getGameInstance().setGameState(Game.GameState.PlayerToMove);
        updateView();
    }

    /**
     * Invoked when the mouse button has been clicked (pressed
     * and released) on a component.
     *
     * @param e the event to be processed
     */
    @Override
    public void mouseClicked(MouseEvent e) {
        // Get the row/col of the click
        int row = e.getY()/20;
        int col = e.getX()/20;
        System.out.println("Clicked on row: " + row + " col: " + col);
        cellClicked(row,col);
    }

    /**
     * Invoked when a mouse button has been pressed on a component.
     *
     * @param e the event to be processed
     */
    @Override
    public void mousePressed(MouseEvent e) {

    }

    /**
     * Invoked when a mouse button has been released on a component.
     *
     * @param e the event to be processed
     */
    @Override
    public void mouseReleased(MouseEvent e) {

    }

    /**
     * Invoked when the mouse enters a component.
     *
     * @param e the event to be processed
     */
    @Override
    public void mouseEntered(MouseEvent e) {

    }

    /**
     * Invoked when the mouse exits a component.
     *
     * @param e the event to be processed
     */
    @Override
    public void mouseExited(MouseEvent e) {

    }
}
