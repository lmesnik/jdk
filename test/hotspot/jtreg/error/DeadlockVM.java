/*
 * @test
 *
 * @summary show the deadlock detection
 * @library /test/lib
 * @build jdk.test.whitebox.WhiteBox
 * @run driver jdk.test.lib.helpers.ClassFileInstaller jdk.test.whitebox.WhiteBox
 * @run main/othervm/timeout=30
 *      -Xbootclasspath/a:.
 *      -XX:+UnlockDiagnosticVMOptions
 *      -XX:+WhiteBoxAPI
 *      -XX:+StartAttachListener
 *      DeadlockVM    
 */
import jdk.test.whitebox.WhiteBox;
public class DeadlockVM {

    public static void main(String[] args) throws Exception {
        WhiteBox wb = WhiteBox.getWhiteBox();
        wb.lock("", 0);
    }
}
