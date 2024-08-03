import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.*;

public class Game {

    //------------------------
    // MEMBER VARIABLES
    //------------------------

    //Game Attributes
    private int playerNum;
    private int currentPlayerTurn = 0;
    private Board board;
    private List<Card> allCards;
    private Murderer murderer;
    private Map<Integer, Player> playerMap;

    private boolean gameRunning = false;
    private boolean gameIsSetup = false;

    private GameView gameView = GameView.getView();
    private int[] currentPlayerMaxMoves;

    private static GameState gameState;
    private static Game gameInstance;

    private boolean currentPlayerHasGuessedOnTurn = false;

    public void currentPlayerGuessed(){
        currentPlayerHasGuessedOnTurn = true;
    }
    public void resetPlayerGuessed(){
        currentPlayerHasGuessedOnTurn = false;
    }
    public boolean getIfCurrentPLayerGuessed(){
        return currentPlayerHasGuessedOnTurn;
    }

    /**
     * Run when guess is submitted
     * guess is true if player choose correctly
     * @param guess
     */
    public void guessMade(boolean guess) {
        if(!guess){
            System.out.println("Wrong guess!");
            GameView.getView().updateInfo("guess wrong");
        }
    }

    /**
     * Handle submitted solve.
     * True when solves correct
     * @param solve
     */
    public void solveMade(boolean solve) {
        if(!solve){
            System.out.println("Wrong solve!");
            GameView.getView().updateInfo("solve wrong");
        }

    }

    enum GameState {
        PlayerToMove,
        WaitingForPlayerToMove,
        PlayerCanSolve,
        PlayerCanGuessAndSolve,
        PlayerWon,
        PlayersLost,
        GameSetup
    }

    //------------------------
    // CONSTRUCTOR
    //------------------------
    public static Game getGameInstance(){
        if (gameInstance!=null) return gameInstance;
        gameInstance = new Game();
        return gameInstance;
    }

    private Game() {
        if(gameState == null) gameState = GameState.GameSetup;
    }

    public int[] getCurrentMaxMoves() {
        return currentPlayerMaxMoves;
    }

    public void performDiceRoll() {
        this.currentPlayerMaxMoves = rollDice();
    }

    public void resetGame() {
        gameIsSetup = false;
        setup();
    }

    public void setGameState(GameState state){
        gameState = state;
    }

    public int getPlayersTurnNum() {
        return currentPlayerTurn;
    }

    public static GameState getState(){ return gameState;}

    public Board getBoard() {
        return board;
    }

    public List<Card> getAllNonMurderCards() {
        return allCards;
    }

    public Murderer getMurderer() {
        return murderer;
    }

    public Map<Integer, Player> getPlayerMap() {
        return playerMap;
    }

    /**
     * Handles setting up the game
     * Does NOT create the players
     */
    public void setup() {
        if(gameIsSetup) return;

        System.out.println("Setting Up Game");
        board = new Board();

        //Create cards
        List<Card> weaponCards = CreateWeaponCards();
        List<Card> characterCards = CreateCharacterCards();
        List<Card> estateCards = CreateEstateCards();

        //Get the murder cards
        Card murderWeapon = weaponCards.remove(getRandomNumber(0, weaponCards.size()));
        Card murderEstate = estateCards.remove(getRandomNumber(0, estateCards.size()));
        Card murderCharacter = characterCards.remove(getRandomNumber(0, characterCards.size()));

        //Picks out a random murder
        murderer = new Murderer(murderWeapon, murderEstate, murderCharacter);

        //Merge and shuffle all cards
        allCards = new ArrayList<>();
        allCards.addAll(weaponCards);
        allCards.addAll(characterCards);
        allCards.addAll(estateCards);

        Collections.shuffle(allCards);

        gameIsSetup = true;
        gameState = GameState.GameSetup;

        resetPlayerGuessed();
    }

    public void setupPlayers(int playerNum) {
        //Create players and order them for turns
        playerMap = CreatePlayers(allCards, playerNum);

        //re add the murder cards to the deck
        allCards.addAll(murderer.getCards());
    }

    /**
     * Handles running the game
     */
    public void run() {
        if (gameRunning) return;

        gameRunning = true;
        while (gameRunning) {
            passOverDevice();

            //Display board at start of turn
            DisplayBoard();

            DisplayTurnInfo();
            //Get a valid input
            boolean validInput = false;

            try {
                InputStreamReader isr = new InputStreamReader(System.in);
                BufferedReader br = new BufferedReader(isr);
                
                int[] dice = rollDice();
                System.out.println("You can move " + dice[2] + " cells");
                System.out.println("Where do you want to move?");

                String input;
                int[] moveBy = new int[2];

                // Get move input
                while (!validInput) {
                    input = br.readLine();
                    input = input.toUpperCase(); // Makes parsing easier

                    if (input.equals("Q") | input.equals("QUIT")) {
                        System.out.println("Stopping Game");
                        return;
                    }

                    try {
                        moveBy = parseInput(input, dice[2]); // x,y
                        validInput = true;
                    } catch (IllegalArgumentException iae) { // If error in parsing
                        System.out.println(ConsoleCommands.RED + "Invalid Move, try again" + ConsoleCommands.RESET);
                        displayMoveHelp();
                    }

                    try {
                        if (!board.isMoveValid(currentPlayerTurn, moveBy[0], moveBy[1])) {
                            System.out.println(ConsoleCommands.RED + "You can't move there! try again" + ConsoleCommands.RESET);
                            validInput = false;
                        }
                    }
                    catch (Door.DoorEnteredEvent doorEnteredEvent){
                        System.out.println("Now entering... " + ConsoleCommands.inBlue(doorEnteredEvent.estate.name));
                        validInput = true;

                    }
                }

            } catch (IOException ioe) {
                System.out.println("IO Exception raised With Move Input");
            }

            nextPlayerTurn();
        }
    }

    /**
     * Move the current player to the specified row/col
     * Only call AFTER checking if valid
     * @param row
     * @param col
     * @throws IOException
     */
    public void moveCurrentPlayerTo(int row, int col) throws IOException {
        System.out.println("Moving player to " + row + "," + col);
        System.out.println("moving " +getCurrentPlayer().getName());
        playerMap.get(currentPlayerTurn).setPositionTo(row,col);
        board.updatePeopleOnBoard();
    }

    /**
     * Returns true if the current player is in an estate
     *
     * @return
     */
    public Optional<Estate> currentPlayerInEstate() {
        Player currentPlayer = playerMap.get(currentPlayerTurn);
        int[] currentPlayerPosition = currentPlayer.getPosition();
        int x = currentPlayerPosition[0];
        int y = currentPlayerPosition[1];
        // for each estate
        // playerIsInside()
        Optional<Estate> estateOptional = getBoard().getEstateList().stream()
                .filter(estate -> estate.playerIsInside(x, y))
                .findAny();

        return estateOptional;
    }

    /**
     * Handles player guessing/solving
     * Only called if player is in an estate
     *
     * @throws IOException
     */
    private void handleAttempt(Estate estate) throws IOException {
        if(playerMap.get(currentPlayerTurn).getHasGuessed()) {
            System.out.println("You have failed a solve attempt and can no longer make guess or solve attempts.");
            System.out.println("Press enter to continue");
            try {
                InputStreamReader isr = new InputStreamReader(System.in);
                BufferedReader bufferedreader = new BufferedReader(isr);
                String enter = bufferedreader.readLine();
            } catch (IOException ioe) {
                System.out.println("IO Exception raised With Guess Input");
            }
            ConsoleCommands.clearScreen();
            return;
        }
        
        // get input from user
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Do you want to guess or solve?");
        boolean validInput = false;
        String input;
        String guessOrSolve = "";
        while (!validInput) {
            input = br.readLine();
            input = input.toUpperCase(); // Makes parsing easier

            // quit
            if (input.equals("Q") | input.equals("QUIT")) {
                System.out.println("Stopping Game");
                return;
            }

            // guess/solve
            if (input.equals("GUESS") | input.equals("SOLVE")) {
                validInput = true;
                guessOrSolve = input;
            } else {
                System.out.println("Invalid input, try again");
            }
        }

        if(guessOrSolve.equals("GUESS")) {
            guess(estate);
        } else if(guessOrSolve.equals("SOLVE")) {
            solve(estate);
        }
    }
    
    /**
     * handles guess attempts
     */
    private void guess(Estate estate) throws IOException {
        // print weapons and characters for guess
        Player currentPlayer = getCurrentPlayer();
        List<String> weapons = getWeapons();
        List<String> characters = getCharacters();
        System.out.println("Weapons: " + ConsoleCommands.RED + weapons + ConsoleCommands.RESET);
        System.out.println("Characters: " + ConsoleCommands.CYAN + characters + ConsoleCommands.RESET);
        System.out.println("Select a " + ConsoleCommands.inRed("weapon") + " for your guess");

        // get weapon from user
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        boolean validInput = false;
        String input;
        String weapon = "";
        while (!validInput) {
            input = br.readLine();
            input = input.toUpperCase(); // Makes parsing easier

            // check if user input a valid weapon
            for (String s : weapons) {
                if (input.equals(s)) {
                    validInput = true;
                    weapon = input;
                    break;
                }
            }
            
            if (!validInput) {
                System.out.println("Enter valid weapon");
            }
        }

        // get character from user
        System.out.println("Select a " + ConsoleCommands.inCyan("character") + " for your guess");
        validInput = false;
        String character = "";
        while (!validInput) {
            input = br.readLine();
            input = input.toUpperCase(); // Makes parsing easier

            if (input.equals("Q") | input.equals("QUIT")) {
                System.out.println("Stopping Game");
                return;
            }

            // check for valid character
            for (String s : characters) {
                if (input.equals(s)) {
                    validInput = true;
                    character = input;
                    break;
                }
            }

            if (!validInput) {
                System.out.println("Enter valid character");
            }
        }

        // print guess
        System.out.println("Your guess is: " + ConsoleCommands.inBlue(character) + " killed in the " + ConsoleCommands.inPurple(estate.name) + " with the " + ConsoleCommands.inRed(weapon));

        int startTurnNumber = currentPlayerTurn;
        int rotationNumber = currentPlayerTurn;

        // goes around all the players to refute the guess
        rotationNumber++;
        if (rotationNumber >= playerNum) rotationNumber = 0;
        while (rotationNumber != startTurnNumber) {
            nextGuessRotation(rotationNumber);

            System.out.println(playerMap.get(currentPlayerTurn).getName() + " guessed that " + character + " killed in the " + estate.name + " with the " + weapon);

            boolean refuted = false;
            // check if any cards player has are contained in the guess
            int cardsContained = 0;
            ArrayList<String> cardsAbleToRefute = new ArrayList<String>();
            for (Card c : playerMap.get(rotationNumber).getCards()) {
                String card = c.getCardName().toUpperCase();
                if (card.equals(character) || card.equals(weapon) || card.equals(estate.name)) {
                    cardsContained++;
                    cardsAbleToRefute.add(card);
                }
            }

            // no refutation
            if(cardsContained == 0) {
                System.out.println("You could not refute the guess");
            // player has 1 card to refute
            } else if (cardsContained == 1) {
                refuted = true;
                System.out.println("You refute the guess using your " + cardsAbleToRefute.get(0) + " card");
            // player has more than 1 card that they can refute with - check which one they want to use
            } else if(cardsContained > 1) {
                refuted = true;
                System.out.println("Your cards: " + playerMap.get(rotationNumber).getCards());
                System.out.println("You can refute the guess using any of the following cards: ");
                System.out.println(cardsAbleToRefute);
                System.out.println("Which card would you like to use to refute the guess?");

                br = new BufferedReader(new InputStreamReader(System.in));
                validInput = false;
                while (!validInput) {
                    input = br.readLine();
                    input = input.toUpperCase(); // Makes parsing easier

                    for (String s : cardsAbleToRefute) {
                        if (input.equals(s)) {
                            validInput = true;
                            break;
                        }
                    }

                    if (!validInput) {
                        System.out.println("Enter valid card");
                    }
                }

            }
            System.out.println("Press enter to continue");
            try {
                InputStreamReader isr = new InputStreamReader(System.in);
                BufferedReader bufferedreader = new BufferedReader(isr);
                String enter = bufferedreader.readLine();
            } catch (IOException ioe) {
                System.out.println("IO Exception raised With Guess Input");
            }
            ConsoleCommands.clearScreen();

            if (refuted) {
                break;
            }
            rotationNumber++;
            if (rotationNumber >= playerNum) rotationNumber = 0;
        }
    }

    /**
     *  go to next character in the refutation rotation
     */
    private void nextGuessRotation(int rotationNumber) {
        System.out.println("Pass over device to " + playerMap.get(rotationNumber).getName());
        System.out.println("Press enter to continue");
        try {
            InputStreamReader isr = new InputStreamReader(System.in);
            BufferedReader bufferedreader = new BufferedReader(isr);
            String enter = bufferedreader.readLine();
        } catch (IOException ioe) {
            System.out.println("IO Exception raised With Guess Input");
        }
        ConsoleCommands.clearScreen();
    }
    
    /**
     * handles solve attempts
     */
    private void solve(Estate estate) throws IOException{
        Player currentPlayer = getCurrentPlayer();
        List<String> weapons = getWeapons();
        List<String> characters = getCharacters();
        List<String> estates = getEstates();

        System.out.println("Weapons: " + ConsoleCommands.RED + weapons + ConsoleCommands.RESET);
        System.out.println("Characters: " + ConsoleCommands.CYAN + characters + ConsoleCommands.RESET);
        System.out.println("Estates: " + ConsoleCommands.PURPLE + estates + ConsoleCommands.RESET);

        System.out.println("Select a " + ConsoleCommands.inRed("weapon") + " for your solve attempt");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        boolean validInput = false;
        String input;
        String weapon = "";
        while (!validInput) {
            input = br.readLine();
            input = input.toUpperCase(); // Makes parsing easier

            for (String s : weapons) {
                if (input.equals(s)) {
                    validInput = true;
                    weapon = input;
                    break;
                }
            }

            if (!validInput) {
                System.out.println("Enter valid weapon");
            }
        }

        System.out.println("Select a " + ConsoleCommands.inCyan("character") + " for your solve attempt");
        validInput = false;
        String character = "";
        while (!validInput) {
            input = br.readLine();
            input = input.toUpperCase(); // Makes parsing easier

            if (input.equals("Q") | input.equals("QUIT")) {
                System.out.println("Stopping Game");
                return;
            }

            for (String s : characters) {
                if (input.equals(s)) {
                    validInput = true;
                    character = input;
                    break;
                }
            }

            if (!validInput) {
                System.out.println("Enter valid character");
            }
        }

        System.out.println("Select a " + ConsoleCommands.inCyan("estate") + " for your solve attempt");
        validInput = false;
        String estateGuessed = "";
        while (!validInput) {
            input = br.readLine();
            input = input.toUpperCase(); // Makes parsing easier

            if (input.equals("Q") | input.equals("QUIT")) {
                System.out.println("Stopping Game");
                return;
            }

            for (String s : estates) {
                if (input.equals(s)) {
                    validInput = true;
                    estateGuessed = input; // was character
                    break;
                }
            }

            if (!validInput) {
                System.out.println("Enter valid estate");
            }
        }

        if(murderer.checkMurderer(getCardByName(weapon), getCardByName(estateGuessed), getCardByName(character))) {
            System.out.println("You win!");
            gameRunning = false;
        } else {
            System.out.println("Your solve attempt was wrong. You can now make no more solve or guess attempts.");
            playerMap.get(currentPlayerTurn).setHasGuessed(true);
            System.out.println("Press enter to continue");
            try {
                InputStreamReader isr = new InputStreamReader(System.in);
                BufferedReader bufferedreader = new BufferedReader(isr);
                String enter = bufferedreader.readLine();
            } catch (IOException ioe) {
                System.out.println("IO Exception raised With Guess Input");
            }
            ConsoleCommands.clearScreen();
        }
    }

    /**
     * gets list of estate cards
     */
    private List<String> getEstates() {
        List<String> estates = new ArrayList<String>();
        for(Card c : allCards) {
            if(c.getCardType() == Card.CardType.Estate) {
                estates.add(c.getCardName().toUpperCase());
            }
        }
        return estates;
    }

    /**
     * gets list of weapon cards
     */
    private List<String> getWeapons() {
        List<String> weapons = new ArrayList<String>();
        for(Card c : allCards) {
            if(c.getCardType() == Card.CardType.Weapon) {
                weapons.add(c.getCardName().toUpperCase());
            }
        }
        return weapons;
    }
    
    /**
     * gets list of character cards
     */
    private List<String> getCharacters() {
        List<String> characters = new ArrayList<String>();
        for(Card c : allCards) {
            if(c.getCardType() == Card.CardType.Character) {
                characters.add(c.getCardName().toUpperCase());
            }
        }
        return characters;
    }

    /**
     * Parses input into a movement array
     * eg input = "UP 3 RIGHT 2"
     * case insensitive
     * returns [x,y] offset
     *
     * @param input
     * @return
     */
    public int[] parseInput(String input, int maxMove) {
        int[] move = new int[2]; // x,y
        Scanner scanner = new Scanner(input);
        System.out.println(input);
        try {
            while (scanner.hasNext()) {
                String direction = scanner.next();
                switch (direction) {
                    case "UP":
                        move[1] -= scanner.nextInt();
                        break;
                    case "DOWN":
                        move[1] += scanner.nextInt();
                        break;
                    case "LEFT":
                        move[0] -= scanner.nextInt();
                        break;
                    case "RIGHT":
                        move[0] += scanner.nextInt();
                        break;
                    default:
                        throw new IllegalArgumentException("Invalid Direction");
                }
            }
        } catch (InputMismatchException ime) {
            throw new IllegalArgumentException("Mismatched input");
        }

        if (Math.abs(move[0]) + Math.abs(move[1]) > maxMove) {
            throw new IllegalArgumentException("Move too large");
        }

        return move;
    }

    private void displayMoveHelp() {
        System.out.println("Enter a move in the form of:");
        System.out.println("UP/DOWN/LEFT/RIGHT <number>");
        System.out.println("eg: UP 3 RIGHT 2");
    }

    /**
     * Rolls dice and returns the result as array
     * [0] = dice 1
     * [1] = dice 2
     * [2] = total
     *
     * @return
     */
    private int[] rollDice() {
        int[] dice = new int[3];
        dice[0] = getRandomNumber(1, 6);
        dice[1] = getRandomNumber(1, 6);
        dice[2] = dice[0] + dice[1];
        System.out.println("You rolled a " + dice[0] + " and a " + dice[1]);
        return dice;
    }

    /**
     * Gives player opportunity to pass over device
     * (So no one sees other players cards)
     */
    private void passOverDevice() {
        ConsoleCommands.clearScreen();
        System.out.println("Pass over device to " + playerMap.get(currentPlayerTurn).getName());
        System.out.println("Press enter to continue");
        try {
            InputStreamReader isr = new InputStreamReader(System.in);
            BufferedReader br = new BufferedReader(isr);
            String input = br.readLine();
        } catch (IOException ioe) {
            System.out.println("IO Exception raised With Move Input");
        }
        ConsoleCommands.clearScreen();
    }

    private int getRandomNumber(int min, int max) {
        return (int) (Math.random() * (max - min) + min);
    }

    /**
     * Creates and returns a list of Weapon cards
     */
    private List<Card> CreateWeaponCards() {
        List<Card> cards = new ArrayList<>();
        cards.add(new Card(Card.CardType.Weapon, "Broom"));
        cards.add(new Card(Card.CardType.Weapon, "Scissors"));
        cards.add(new Card(Card.CardType.Weapon, "Knife"));
        cards.add(new Card(Card.CardType.Weapon, "Shovel"));
        cards.add(new Card(Card.CardType.Weapon, "IPad"));
        return cards;
    }

    /**
     * Creates and returns a list of Character cards
     */
    private List<Card> CreateCharacterCards() {
        List<Card> cards = new ArrayList<>();
        cards.add(new Card(Card.CardType.Character, "Lucillia"));
        cards.add(new Card(Card.CardType.Character, "Bert"));
        cards.add(new Card(Card.CardType.Character, "Malina"));
        cards.add(new Card(Card.CardType.Character, "Percy"));
        return cards;
    }

    /**
     * Creates and returns a list of Estate cards
     */
    private List<Card> CreateEstateCards() {
        List<Card> cards = new ArrayList<>();
        cards.add(new Card(Card.CardType.Estate, "Haunted House"));
        cards.add(new Card(Card.CardType.Estate, "Manic Manor"));
        cards.add(new Card(Card.CardType.Estate, "Visitation Villa"));
        cards.add(new Card(Card.CardType.Estate, "Calamity Castle"));
        cards.add(new Card(Card.CardType.Estate, "Peril Palace"));
        return cards;
    }

    /**
     * Creates players and allocates cards to them
     */
    Map<Integer, Player> CreatePlayers(List<Card> cards, int playerNum) {
        this.playerNum = playerNum;

        if (playerNum != 3 && playerNum != 4) throw new IllegalArgumentException("Can only create 3-4 players (tried " + playerNum + ")");

        //Only handling 3 or 4 players case
        List<Player> players = new ArrayList<>(List.of(
                new Player("Lucilla").setStartPosition(11, 1),
                new Player("Bert").setStartPosition(1, 9),
                new Player("Malina").setStartPosition(9, 22),
                new Player("Percy").setStartPosition(22, 14)
        ));

        //Remove Player if only 3
        if(playerNum==3) players.remove(3);

        //Goes through every card
        int i = 0;
        while (i < cards.size()) {
            //Adds a card to each player until no cards are left
            for (Player p : players) {
                p.addCard(cards.get(i));
                i++;
                if (i >= cards.size()) break;
            }
        }

        //Turn order
        var playerMap = new HashMap<Integer, Player>();

        int numAdded = 0;
        int it = getRandomNumber(0,3);
        while (numAdded < playerNum){
            if(it == playerNum){
                it = 0;
            }
            playerMap.put(numAdded, players.get(it));
            it++;
            numAdded++;
        }

        board.BuildPeople(playerMap); // Build people on board

        return playerMap;
    }


    /**
     * Gets and displays the board to the screen
     */
    private void DisplayBoard() {
        this.board.displayBoard();
    }

    /**
     * Displays who's turn it is
     */
    private void DisplayTurnInfo() {
        System.out.println("Player " + (currentPlayerTurn + 1) + "'s turn: " +
               getCurrentPlayer().toString());
    }

    /**
     * Sets to next player turn
     */
    public void nextPlayerTurn() {
        System.out.println("End turn");
        currentPlayerTurn++;
        if (currentPlayerTurn >= playerNum) currentPlayerTurn = 0;
    }

    /**
     * returns the card class of a card by its name, returns null if cant be found
     */
    public Card getCardByName(String cardName) {

        for (Card c : allCards) {

            if (c.getCardName().toUpperCase().equals(cardName.toUpperCase())) return c;
        }
        return null;
    }
    
    /**
     * gets current player
     */
    public Player getCurrentPlayer() {
        return playerMap.get(currentPlayerTurn);
    }
}

class ConsoleCommands {
    public static final String RED = "\033[0;31m";     // RED
    public static final String GREEN = "\033[0;32m";   // GREEN
    public static final String BLUE = "\033[0;34m";    // BLUE
    public static final String PURPLE = "\033[0;35m";  // PURPLE
    public static final String CYAN = "\033[0;36m";    // CYAN
    public static final String RESET = "\033[0m";  // Text Reset
    public static final String YELLOW_BOLD = "\033[1;33m"; // YELLOW

    public static boolean useColour = true;
    public static String inYellow(String text){
       return inText(text, YELLOW_BOLD);
    }

    public static String inRed(String text){
        return inText(text, RED);
    }
    public static String inGreen(String text){
        return inText(text, GREEN);
    }

    public static String inBlue(String text){
       return inText(text, BLUE);
    }

    public static String inPurple(String text){
       return inText(text, PURPLE);
    }

    public static String inCyan(String text){
        return inText(text, CYAN);
    }

    public static String inText(String text, String color){
        if(!useColour) return text;
        return color + text + RESET;
    }

    public static void clearScreen() {
        System.out.println(System.lineSeparator().repeat(50));
        System.out.print("\033[H\033[2J");
        System.out.flush();
    }
}
