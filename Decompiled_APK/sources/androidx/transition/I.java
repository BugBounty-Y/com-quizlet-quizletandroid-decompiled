package androidx.transition;

import android.view.View;
import java.util.ArrayList;
import java.util.HashMap;

/* loaded from: classes.dex */
public final class I {
    public final View b;
    public final HashMap a = new HashMap();
    public final ArrayList c = new ArrayList();

    public I(View view) {
        this.b = view;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof I)) {
            return false;
        }
        I i = (I) obj;
        return this.b == i.b && this.a.equals(i.a);
    }

    public final int hashCode() {
        return this.a.hashCode() + (this.b.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sbX = android.support.v4.media.session.a.x("TransitionValues@" + Integer.toHexString(hashCode()) + ":\n", "    view = ");
        sbX.append(this.b);
        sbX.append("\n");
        String strK = android.support.v4.media.session.a.k(sbX.toString(), "    values:");
        HashMap map = this.a;
        for (String str : map.keySet()) {
            strK = strK + "    " + str + ": " + map.get(str) + "\n";
        }
        return strK;
    }
}
