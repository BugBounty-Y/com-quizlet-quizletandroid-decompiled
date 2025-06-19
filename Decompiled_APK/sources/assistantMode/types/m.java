package assistantMode.types;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_camera.k3;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class m extends k3 {
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final kotlin.u f;
    public final kotlin.u g;

    public m(String plain, String str, String languageCode, String oppositeSidePlainText, String oppositeSideLanguageCode) {
        Intrinsics.checkNotNullParameter(plain, "plain");
        Intrinsics.checkNotNullParameter(languageCode, "languageCode");
        Intrinsics.checkNotNullParameter(oppositeSidePlainText, "oppositeSidePlainText");
        Intrinsics.checkNotNullParameter(oppositeSideLanguageCode, "oppositeSideLanguageCode");
        this.a = plain;
        this.b = str;
        this.c = languageCode;
        this.d = oppositeSidePlainText;
        this.e = oppositeSideLanguageCode;
        this.f = kotlin.l.b(new l(this, 0));
        this.g = kotlin.l.b(new l(this, 1));
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.k3
    public final assistantMode.utils.classification.classifierTypes.a b() {
        return (assistantMode.utils.classification.classifierTypes.a) this.f.getValue();
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.k3
    public final String c() {
        return this.c;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.k3
    public final assistantMode.utils.classification.classifierTypes.b d() {
        return (assistantMode.utils.classification.classifierTypes.b) this.g.getValue();
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.k3
    public final String e() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof m)) {
            return false;
        }
        m mVar = (m) obj;
        return Intrinsics.b(this.a, mVar.a) && Intrinsics.b(this.b, mVar.b) && Intrinsics.b(this.c, mVar.c) && Intrinsics.b(this.d, mVar.d) && Intrinsics.b(this.e, mVar.e);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.k3
    public final String f() {
        return this.b;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        return this.e.hashCode() + d0.e(d0.e((iHashCode + (str == null ? 0 : str.hashCode())) * 31, 31, this.c), 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("LazyAnnotatedText(plain=");
        sb.append(this.a);
        sb.append(", rich=");
        sb.append(this.b);
        sb.append(", languageCode=");
        sb.append(this.c);
        sb.append(", oppositeSidePlainText=");
        sb.append(this.d);
        sb.append(", oppositeSideLanguageCode=");
        return android.support.v4.media.session.a.t(sb, this.e, ")");
    }
}
