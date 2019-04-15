package eu.rcauth.delegserver.oauth2.exceptions;

/**
 * Exception used when two Unique Attribute Lists are different. Usually this means
 * that the hash constructed from the current set of user attributes does not
 * match the attribute hash stored in a trace record.
 *
 * @author "Tamás Balogh"
 *
 */
public class AttributeMismatchException extends Exception {

    public AttributeMismatchException() {
        super();
    }

    public AttributeMismatchException(String msg) {
        super(msg);
    }

}
