package org.wordpress.aztec.watchers.event.sequence.known.space;

import android.text.Editable;
import android.text.SpannableStringBuilder;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.watchers.event.sequence.c;
import org.wordpress.aztec.watchers.event.text.e;

/* loaded from: classes3.dex */
public final class a extends c {
    public final char b = ' ';
    public final String c = " ";

    public a() {
        org.wordpress.aztec.watchers.event.sequence.known.space.steps.b bVarC = new org.wordpress.aztec.watchers.event.sequence.known.space.steps.a(0).c();
        org.wordpress.aztec.watchers.event.sequence.known.space.steps.b bVarC2 = new org.wordpress.aztec.watchers.event.sequence.known.space.steps.a(0).c();
        org.wordpress.aztec.watchers.event.sequence.known.space.steps.c cVarD = new org.wordpress.aztec.watchers.event.sequence.known.space.steps.a(1).d();
        org.wordpress.aztec.watchers.event.sequence.known.space.steps.c cVarD2 = new org.wordpress.aztec.watchers.event.sequence.known.space.steps.a(1).d();
        this.a.clear();
        a(bVarC);
        a(bVarC2);
        a(cVarD);
        a(cVarD2);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // org.wordpress.aztec.watchers.event.sequence.c
    public final org.wordpress.aztec.watchers.event.sequence.known.space.steps.c b(org.wordpress.aztec.watchers.event.sequence.a sequence) {
        Intrinsics.checkNotNullParameter(sequence, "sequence");
        org.wordpress.aztec.watchers.event.sequence.known.space.steps.a aVar = new org.wordpress.aztec.watchers.event.sequence.known.space.steps.a(1);
        e eVar = (e) CollectionsKt.L(sequence);
        E e = sequence.get(sequence.size() - 1);
        Intrinsics.checkNotNullExpressionValue(e, "get(...)");
        SpannableStringBuilder spannableStringBuilder = eVar.a.a;
        int iA = org.apache.commons.lang3.e.a(spannableStringBuilder, ((e) e).c.a);
        if (spannableStringBuilder != null) {
            spannableStringBuilder.insert(iA, (CharSequence) this.c);
        }
        org.wordpress.aztec.watchers.event.text.a aVar2 = new org.wordpress.aztec.watchers.event.text.a(spannableStringBuilder);
        Intrinsics.checkNotNullParameter(aVar2, "<set-?>");
        aVar.c = aVar2;
        org.wordpress.aztec.watchers.event.sequence.known.space.steps.c cVarD = aVar.d();
        cVarD.f = iA;
        cVarD.g = 1;
        return cVarD;
    }

    @Override // org.wordpress.aztec.watchers.event.sequence.c
    public final org.wordpress.aztec.watchers.event.sequence.b d(org.wordpress.aztec.watchers.event.sequence.a sequence) {
        Intrinsics.checkNotNullParameter(sequence, "sequence");
        if (this.a.size() == sequence.size()) {
            if (!e(sequence)) {
                return org.wordpress.aztec.watchers.event.sequence.b.b;
            }
            e eVar = (e) CollectionsKt.L(sequence);
            e eVar2 = (e) CollectionsKt.U(sequence);
            SpannableStringBuilder spannableStringBuilder = eVar.a.a;
            if (spannableStringBuilder != null) {
                int length = spannableStringBuilder.length();
                Intrinsics.d(eVar2.c.a);
                if (length == r2.length() - 1) {
                    org.wordpress.aztec.watchers.event.text.b bVar = eVar.a;
                    Editable editable = eVar2.c.a;
                    Intrinsics.d(editable);
                    if (editable.charAt(bVar.b + bVar.c) == this.b) {
                        return !c.c(bVar) ? org.wordpress.aztec.watchers.event.sequence.b.a : org.wordpress.aztec.watchers.event.sequence.b.c;
                    }
                }
            }
        }
        return org.wordpress.aztec.watchers.event.sequence.b.b;
    }
}
