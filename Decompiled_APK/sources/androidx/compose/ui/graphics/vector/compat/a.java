package androidx.compose.ui.graphics.vector.compat;

import android.content.res.TypedArray;
import android.content.res.XmlResourceParser;
import androidx.appcompat.app.Q;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public final XmlResourceParser a;
    public int b = 0;
    public final Q c;

    public a(XmlResourceParser xmlResourceParser) {
        this.a = xmlResourceParser;
        Q q = new Q();
        q.a = new float[64];
        this.c = q;
    }

    public final float a(TypedArray typedArray, String str, int i, float f) {
        if (androidx.core.content.res.b.e(this.a, str)) {
            f = typedArray.getFloat(i, f);
        }
        b(typedArray.getChangingConfigurations());
        return f;
    }

    public final void b(int i) {
        this.b = i | this.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && this.b == aVar.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AndroidVectorParser(xmlParser=");
        sb.append(this.a);
        sb.append(", config=");
        return android.support.v4.media.session.a.q(sb, this.b, ')');
    }
}
