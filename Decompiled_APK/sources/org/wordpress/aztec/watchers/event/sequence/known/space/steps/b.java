package org.wordpress.aztec.watchers.event.sequence.known.space.steps;

import android.text.Editable;
import android.text.SpannableStringBuilder;
import com.google.android.gms.internal.mlkit_vision_camera.Y2;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.watchers.event.text.e;

/* loaded from: classes3.dex */
public final class b extends e {
    public final /* synthetic */ int e;
    public SpannableStringBuilder f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ b(org.wordpress.aztec.watchers.event.text.b bVar, org.wordpress.aztec.watchers.event.text.c cVar, org.wordpress.aztec.watchers.event.text.a aVar, int i) {
        super(bVar, cVar, aVar);
        this.e = i;
    }

    @Override // org.wordpress.aztec.watchers.event.text.e
    public final boolean a() {
        switch (this.e) {
            case 0:
                org.wordpress.aztec.watchers.event.text.b bVar = this.a;
                SpannableStringBuilder spannableStringBuilder = bVar.a;
                this.f = spannableStringBuilder;
                int i = bVar.c;
                if (i > 0 && bVar.d == 0) {
                    int i2 = bVar.b + i;
                    Intrinsics.d(spannableStringBuilder);
                    if (i2 <= spannableStringBuilder.length()) {
                        org.wordpress.aztec.watchers.event.text.c cVar = this.b;
                        if (cVar.b >= 0 && cVar.d == 0) {
                            SpannableStringBuilder spannableStringBuilder2 = cVar.a;
                            Intrinsics.d(spannableStringBuilder2);
                            int length = spannableStringBuilder2.length();
                            SpannableStringBuilder spannableStringBuilder3 = this.f;
                            Intrinsics.d(spannableStringBuilder3);
                            if (length < spannableStringBuilder3.length()) {
                                org.wordpress.aztec.watchers.event.text.a aVar = this.c;
                                SpannableStringBuilder spannableStringBuilder4 = this.f;
                                Intrinsics.d(spannableStringBuilder4);
                                int iE = Y2.e(spannableStringBuilder4);
                                Editable editable = aVar.a;
                                Intrinsics.d(editable);
                                if (iE > Y2.e(editable)) {
                                }
                            }
                        }
                    }
                }
                break;
            default:
                org.wordpress.aztec.watchers.event.text.b bVar2 = this.a;
                this.f = bVar2.a;
                if (bVar2.c == 0 && bVar2.d > 0) {
                    org.wordpress.aztec.watchers.event.text.c cVar2 = this.b;
                    if (cVar2.b >= 0 && cVar2.d > 0) {
                        SpannableStringBuilder spannableStringBuilder5 = cVar2.a;
                        Intrinsics.d(spannableStringBuilder5);
                        if (spannableStringBuilder5.length() > 0) {
                            org.wordpress.aztec.watchers.event.text.a aVar2 = this.c;
                            SpannableStringBuilder spannableStringBuilder6 = this.f;
                            Intrinsics.d(spannableStringBuilder6);
                            int iE2 = Y2.e(spannableStringBuilder6);
                            Editable editable2 = aVar2.a;
                            Intrinsics.d(editable2);
                            if (iE2 == Y2.e(editable2)) {
                            }
                        }
                    }
                }
                break;
        }
        return false;
    }
}
