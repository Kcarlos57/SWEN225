import java.io.*;

import org.junit.*;
import org.junit.jupiter.api.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class GameTests {
    private final InputStream systemIn = System.in;
    private final PrintStream systemOut = System.out;

    private Game game;

    private ByteArrayInputStream testIn;
    private ByteArrayOutputStream testOut;

    @Before
    public void setUpOutput() {
        testOut = new ByteArrayOutputStream();
        System.setOut(new PrintStream(testOut));
    }

    @After
    public void restoreSystemInputOutput() {
        System.setIn(systemIn);
        System.setOut(systemOut);
    }

    private void provideInput(String data) {
        testIn = new ByteArrayInputStream(data.getBytes());
        System.setIn(testIn);
    }

    public void initGame() { // Start a new game
        game = Game.getGameInstance();
        game.setup();
        ConsoleCommands.useColour = false; // stop use colour
        provideInput("4\n"); // 4 players
        System.out.println("Game started"); // FIXME - Can't get tests to get past here
    }


    @Test
    public void displayBoardAtStartup() {
        assert false;
        initGame();
        String board = game.getBoard().displayBoard();
        String shouldBe = """
                _|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
                _|_|_|_|_|_|_|_|_|_|_|L|_|_|_|_|_|_|_|_|_|_|_|_|
                _|_|I|I|I|I|I|_|_|_|_|_|_|_|_|_|_|I|I|I|I|I|_|_|
                _|_|I|I|I|I|D|_|_|_|_|_|_|_|_|_|_|I|I|I|I|I|_|_|
                _|_|I|I|I|I|I|_|_|_|_|_|_|_|_|_|_|I|I|I|I|I|_|_|
                _|_|I|I|I|I|I|_|_|_|_|W|W|_|_|_|_|D|I|I|I|I|_|_|
                _|_|I|I|I|D|I|_|_|_|_|W|W|_|_|_|_|I|I|I|D|I|_|_|
                _|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
                _|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
                _|B|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
                _|_|_|_|_|_|_|_|_|I|I|I|D|I|I|_|_|_|_|_|_|_|_|_|
                _|_|_|_|_|W|W|_|_|I|I|I|I|I|D|_|_|W|W|_|_|_|_|_|
                _|_|_|_|_|W|W|_|_|D|I|I|I|I|I|_|_|W|W|_|_|_|_|_|
                _|_|_|_|_|_|_|_|_|I|I|D|I|I|I|_|_|_|_|_|_|_|_|_|
                _|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|P|_|
                _|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
                _|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
                _|_|I|D|I|I|I|_|_|_|_|W|W|_|_|_|_|I|D|I|I|I|_|_|
                _|_|I|I|I|I|D|_|_|_|_|W|W|_|_|_|_|I|I|I|I|I|_|_|
                _|_|I|I|I|I|I|_|_|_|_|_|_|_|_|_|_|I|I|I|I|I|_|_|
                _|_|I|I|I|I|I|_|_|_|_|_|_|_|_|_|_|D|I|I|I|I|_|_|
                _|_|I|I|I|I|I|_|_|_|_|_|_|_|_|_|_|I|I|I|I|I|_|_|
                _|_|_|_|_|_|_|_|_|M|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
                _|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
                                
                GLOSSARY OF SYMBOLS:
                | W = WALL           |
                | I = ESTATE WALL    |
                | P = PERSON         |
                | D = DOOR OF ESTATE |"""; // This is the board that should be displayed

        assertEquals(board, shouldBe);
    }

    @Test
    public void testValidPlayerMovement() {
        assert false;
        initGame();
        // Tests is player movement gets displayed correctly on board
        Player p1 = game.getPlayerMap().get(0); // get luccila
        p1.setPositionWithOffset(4, 3); // RIGHT 4 DOWN 3
        game.getBoard().updatePeopleOnBoard();
        String board = game.getBoard().displayBoard();

        String shouldBe = """
                _|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
                _|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
                _|_|I|I|I|I|I|_|_|_|_|_|_|_|_|_|_|I|I|I|I|I|_|_|
                _|_|I|I|I|I|D|_|_|_|_|_|_|_|_|_|_|I|I|I|I|I|_|_|
                _|_|I|I|I|I|I|_|_|_|_|_|_|_|_|L|_|I|I|I|I|I|_|_|
                _|_|I|I|I|I|I|_|_|_|_|W|W|_|_|_|_|D|I|I|I|I|_|_|
                _|_|I|I|I|D|I|_|_|_|_|W|W|_|_|_|_|I|I|I|D|I|_|_|
                _|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
                _|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
                _|B|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
                _|_|_|_|_|_|_|_|_|I|I|I|D|I|I|_|_|_|_|_|_|_|_|_|
                _|_|_|_|_|W|W|_|_|I|I|I|I|I|D|_|_|W|W|_|_|_|_|_|
                _|_|_|_|_|W|W|_|_|D|I|I|I|I|I|_|_|W|W|_|_|_|_|_|
                _|_|_|_|_|_|_|_|_|I|I|D|I|I|I|_|_|_|_|_|_|_|_|_|
                _|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|P|_|
                _|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
                _|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
                _|_|I|D|I|I|I|_|_|_|_|W|W|_|_|_|_|I|D|I|I|I|_|_|
                _|_|I|I|I|I|D|_|_|_|_|W|W|_|_|_|_|I|I|I|I|I|_|_|
                _|_|I|I|I|I|I|_|_|_|_|_|_|_|_|_|_|I|I|I|I|I|_|_|
                _|_|I|I|I|I|I|_|_|_|_|_|_|_|_|_|_|D|I|I|I|I|_|_|
                _|_|I|I|I|I|I|_|_|_|_|_|_|_|_|_|_|I|I|I|I|I|_|_|
                _|_|_|_|_|_|_|_|_|M|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
                _|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
                                
                GLOSSARY OF SYMBOLS:
                | W = WALL           |
                | I = ESTATE WALL    |
                | P = PERSON         |
                | D = DOOR OF ESTATE |"""; // This is the board that should be displayed

        assertEquals(board, shouldBe);
    }

    /**
     * Moving more than max move
     */
    @Test
    public void testOverMax() {
        Game gameTemp = Game.getGameInstance();

        assertThrows(IllegalArgumentException.class,
                () -> gameTemp.parseInput("UP 5 LEFT 2", 10)
        );

        assertThrows(IllegalArgumentException.class,
                () -> gameTemp.parseInput("UP 2 LEFT 5", 10)
        );
    }

    @Test
    public void testInvalidDirection() {
        Game gameTemp = Game.getGameInstance();

        assertThrows(IllegalArgumentException.class,
                () -> gameTemp.parseInput("BLEH 5 LEFT 2", 10)
        );

        assertThrows(IllegalArgumentException.class,
                () -> gameTemp.parseInput("UP 5 LBEH 2", 10)
        );
    }

    @Test
    public void testInvalidInput() {
        Game gameTemp = Game.getGameInstance();

        assertThrows(IllegalArgumentException.class,
                () -> gameTemp.parseInput("5 UP LEFT 10", 10)
        );

        assertThrows(IllegalArgumentException.class,
                () -> gameTemp.parseInput("UP UP LEFT LEFT", 10)
        );
    }

    @Test
    public void testInvalidMoveNumber() {
        Game gameTemp = Game.getGameInstance();

        assertThrows(IllegalArgumentException.class,
                () -> gameTemp.parseInput("UP -1 LEFT 2", 10)
        );

        assertThrows(IllegalArgumentException.class,
                () -> gameTemp.parseInput("UP 0 LEFT 2", 10)
        );
    }

    @Test
    public void testEmptyInput() {
        Game gameTemp = Game.getGameInstance();

        assertThrows(IllegalArgumentException.class,
                () -> gameTemp.parseInput("", 10)
        );
    }

    @Test
    public void testDuplicateDirections() {
        Game gameTemp = Game.getGameInstance();

        assertThrows(IllegalArgumentException.class,
                () -> gameTemp.parseInput("UP UP LEFT 2", 10)
        );
    }

    @Test
    public void testInvalidCombinationOfMoveNumberAndDirection() {
        Game gameTemp = Game.getGameInstance();

        assertThrows(IllegalArgumentException.class,
                () -> gameTemp.parseInput("UP 11 LEFT 2", 10)
        );
    }

    @Test
    public void testInvalidCharacterInDirection() {
        Game gameTemp = Game.getGameInstance();

        assertThrows(IllegalArgumentException.class,
                () -> gameTemp.parseInput("UP 5 L&H 2", 10)
        );
    }


}