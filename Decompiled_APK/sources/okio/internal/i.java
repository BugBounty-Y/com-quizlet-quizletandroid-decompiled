package okio.internal;

import java.io.IOException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.J;
import okio.A;

/* loaded from: classes3.dex */
public final /* synthetic */ class i implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ J b;
    public final /* synthetic */ A c;
    public final /* synthetic */ J d;
    public final /* synthetic */ J e;

    public /* synthetic */ i(J j, A a, J j2, J j3) {
        this.b = j;
        this.c = a;
        this.d = j2;
        this.e = j3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) throws IOException {
        int i = this.a;
        int iIntValue = ((Integer) obj).intValue();
        Long l = (Long) obj2;
        switch (i) {
            case 0:
                long jLongValue = l.longValue();
                if (iIntValue == 21589) {
                    if (jLongValue < 1) {
                        throw new IOException("bad zip: extended timestamp extra too short");
                    }
                    A a = this.c;
                    byte b = a.readByte();
                    boolean z = (b & 1) == 1;
                    boolean z2 = (b & 2) == 2;
                    boolean z3 = (b & 4) == 4;
                    long j = z ? 5L : 1L;
                    if (z2) {
                        j += 4;
                    }
                    if (z3) {
                        j += 4;
                    }
                    if (jLongValue < j) {
                        throw new IOException("bad zip: extended timestamp extra too short");
                    }
                    if (z) {
                        this.b.a = Integer.valueOf(a.j());
                    }
                    if (z2) {
                        this.d.a = Integer.valueOf(a.j());
                    }
                    if (z3) {
                        this.e.a = Integer.valueOf(a.j());
                    }
                }
                return Unit.a;
            default:
                long jLongValue2 = l.longValue();
                if (iIntValue == 1) {
                    J j2 = this.b;
                    if (j2.a != null) {
                        throw new IOException("bad zip: NTFS extra attribute tag 0x0001 repeated");
                    }
                    if (jLongValue2 != 24) {
                        throw new IOException("bad zip: NTFS extra attribute tag 0x0001 size != 24");
                    }
                    A a2 = this.c;
                    j2.a = Long.valueOf(a2.l());
                    this.d.a = Long.valueOf(a2.l());
                    this.e.a = Long.valueOf(a2.l());
                }
                return Unit.a;
        }
    }

    public /* synthetic */ i(A a, J j, J j2, J j3) {
        this.c = a;
        this.b = j;
        this.d = j2;
        this.e = j3;
    }
}
