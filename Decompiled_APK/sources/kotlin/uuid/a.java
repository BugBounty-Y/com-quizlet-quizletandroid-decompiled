package kotlin.uuid;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import java.io.Serializable;
import kotlin.text.D;

/* loaded from: classes3.dex */
public final class a implements Serializable {
    public static final com.quizlet.quizletandroid.ui.activitycenter.models.a c = new com.quizlet.quizletandroid.ui.activitycenter.models.a();
    public static final a d = new a(0, 0);
    public final long a;
    public final long b;

    public a(long j, long j2) {
        this.a = j;
        this.b = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && this.b == aVar.b;
    }

    public final int hashCode() {
        long j = this.a ^ this.b;
        return ((int) j) ^ ((int) (j >> 32));
    }

    public final String toString() {
        byte[] bArr = new byte[36];
        long j = this.b;
        AbstractC3405w1.b(j, bArr, 24, 6);
        bArr[23] = 45;
        AbstractC3405w1.b(j >>> 48, bArr, 19, 2);
        bArr[18] = 45;
        long j2 = this.a;
        AbstractC3405w1.b(j2, bArr, 14, 2);
        bArr[13] = 45;
        AbstractC3405w1.b(j2 >>> 16, bArr, 9, 2);
        bArr[8] = 45;
        AbstractC3405w1.b(j2 >>> 32, bArr, 0, 4);
        return D.i(bArr);
    }
}
