package androidx.compose.ui.text.style;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_barcode.U5;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class j {
    public static final j b = new j(0);
    public static final j c = new j(1);
    public static final j d = new j(2);
    public final int a;

    public j(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof j) {
            return this.a == ((j) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return this.a;
    }

    public final String toString() {
        int i = this.a;
        if (i == 0) {
            return "TextDecoration.None";
        }
        ArrayList arrayList = new ArrayList();
        if ((i & 1) != 0) {
            arrayList.add("Underline");
        }
        if ((i & 2) != 0) {
            arrayList.add("LineThrough");
        }
        if (arrayList.size() != 1) {
            return d0.r(new StringBuilder("TextDecoration["), U5.b(arrayList, ", ", null, 62), ']');
        }
        return "TextDecoration." + ((String) arrayList.get(0));
    }
}
