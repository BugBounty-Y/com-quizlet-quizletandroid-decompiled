package androidx.constraintlayout.core.parser;

import com.amazon.device.ads.DtbDeviceDataRetriever;

/* loaded from: classes.dex */
public class CLParsingException extends Exception {
    public final String a;
    public final String b;

    public CLParsingException(String str, c cVar) {
        super(str);
        this.a = str;
        if (cVar != null) {
            this.b = cVar.h();
        } else {
            this.b = DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;
        }
    }

    @Override // java.lang.Throwable
    public final String toString() {
        StringBuilder sb = new StringBuilder("CLParsingException (");
        sb.append(hashCode());
        sb.append(") : ");
        sb.append(this.a + " (" + this.b + " at line 0)");
        return sb.toString();
    }
}
