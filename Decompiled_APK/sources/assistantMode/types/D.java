package assistantMode.types;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_camera.k3;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class D extends k3 {
    public final String a;
    public final String b;
    public final String c;

    public D(String plain, String str, String languageCode) {
        Intrinsics.checkNotNullParameter(plain, "plain");
        Intrinsics.checkNotNullParameter(languageCode, "languageCode");
        this.a = plain;
        this.b = str;
        this.c = languageCode;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.k3
    public final assistantMode.utils.classification.classifierTypes.a b() {
        return null;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.k3
    public final String c() {
        return this.c;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.k3
    public final assistantMode.utils.classification.classifierTypes.b d() {
        return null;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.k3
    public final String e() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof D)) {
            return false;
        }
        D d = (D) obj;
        return Intrinsics.b(this.a, d.a) && Intrinsics.b(this.b, d.b) && Intrinsics.b(this.c, d.c);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.k3
    public final String f() {
        return this.b;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        return d0.e((iHashCode + (str == null ? 0 : str.hashCode())) * 31, 961, this.c);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StaticAnnotatedText(plain=");
        sb.append(this.a);
        sb.append(", rich=");
        sb.append(this.b);
        sb.append(", languageCode=");
        return android.support.v4.media.session.a.t(sb, this.c, ", entity=null, partOfSpeech=null)");
    }
}
