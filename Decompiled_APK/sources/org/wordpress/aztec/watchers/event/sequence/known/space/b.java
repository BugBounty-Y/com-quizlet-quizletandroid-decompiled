package org.wordpress.aztec.watchers.event.sequence.known.space;

import android.text.Editable;
import android.text.SpannableStringBuilder;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.watchers.event.sequence.c;
import org.wordpress.aztec.watchers.event.text.e;

/* loaded from: classes3.dex */
public final class b extends c {
    public final /* synthetic */ int b;

    public /* synthetic */ b(int i) {
        this.b = i;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // org.wordpress.aztec.watchers.event.sequence.c
    public final org.wordpress.aztec.watchers.event.sequence.known.space.steps.c b(org.wordpress.aztec.watchers.event.sequence.a sequence) {
        switch (this.b) {
            case 0:
                Intrinsics.checkNotNullParameter(sequence, "sequence");
                org.wordpress.aztec.watchers.event.sequence.known.space.steps.a aVar = new org.wordpress.aztec.watchers.event.sequence.known.space.steps.a(1);
                org.wordpress.aztec.watchers.event.text.b bVar = ((e) CollectionsKt.L(sequence)).a;
                SpannableStringBuilder spannableStringBuilder = bVar.a;
                int i = bVar.b;
                if (spannableStringBuilder != null) {
                    spannableStringBuilder.insert(i, (CharSequence) "\n");
                }
                org.wordpress.aztec.watchers.event.text.a aVar2 = new org.wordpress.aztec.watchers.event.text.a(spannableStringBuilder);
                Intrinsics.checkNotNullParameter(aVar2, "<set-?>");
                aVar.c = aVar2;
                org.wordpress.aztec.watchers.event.sequence.known.space.steps.c cVarD = aVar.d();
                cVarD.f = i;
                cVarD.g = 1;
                return cVarD;
            default:
                Intrinsics.checkNotNullParameter(sequence, "sequence");
                org.wordpress.aztec.watchers.event.sequence.known.space.steps.a aVar3 = new org.wordpress.aztec.watchers.event.sequence.known.space.steps.a(1);
                e eVar = (e) CollectionsKt.L(sequence);
                E e = sequence.get(sequence.size() - 1);
                Intrinsics.checkNotNullExpressionValue(e, "get(...)");
                SpannableStringBuilder spannableStringBuilder2 = eVar.a.a;
                int iA = org.apache.commons.lang3.e.a(spannableStringBuilder2, ((e) e).c.a);
                if (spannableStringBuilder2 != null) {
                    spannableStringBuilder2.insert(iA, (CharSequence) "\n");
                }
                org.wordpress.aztec.watchers.event.text.a aVar4 = new org.wordpress.aztec.watchers.event.text.a(spannableStringBuilder2);
                Intrinsics.checkNotNullParameter(aVar4, "<set-?>");
                aVar3.c = aVar4;
                org.wordpress.aztec.watchers.event.sequence.known.space.steps.c cVarD2 = aVar3.d();
                cVarD2.f = iA;
                cVarD2.g = 1;
                return cVarD2;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // org.wordpress.aztec.watchers.event.sequence.c
    public final org.wordpress.aztec.watchers.event.sequence.b d(org.wordpress.aztec.watchers.event.sequence.a sequence) {
        switch (this.b) {
            case 0:
                Intrinsics.checkNotNullParameter(sequence, "sequence");
                if (this.a.size() == sequence.size()) {
                    if (!e(sequence)) {
                        break;
                    } else {
                        e eVar = (e) CollectionsKt.L(sequence);
                        e eVar2 = (e) CollectionsKt.U(sequence);
                        E e = sequence.get(1);
                        Intrinsics.checkNotNullExpressionValue(e, "get(...)");
                        e eVar3 = (e) e;
                        SpannableStringBuilder spannableStringBuilder = eVar.a.a;
                        if (spannableStringBuilder != null) {
                            int length = spannableStringBuilder.length();
                            Editable editable = eVar2.c.a;
                            Intrinsics.d(editable);
                            if (length == editable.length()) {
                                SpannableStringBuilder spannableStringBuilder2 = eVar3.b.a;
                                Intrinsics.d(spannableStringBuilder2);
                                if (spannableStringBuilder2.charAt(eVar3.b.b) == '\n') {
                                    break;
                                }
                            }
                        }
                    }
                }
                break;
            default:
                Intrinsics.checkNotNullParameter(sequence, "sequence");
                if (this.a.size() == sequence.size()) {
                    if (!e(sequence)) {
                        break;
                    } else {
                        e eVar4 = (e) CollectionsKt.L(sequence);
                        e eVar5 = (e) CollectionsKt.U(sequence);
                        SpannableStringBuilder spannableStringBuilder3 = eVar4.a.a;
                        if (spannableStringBuilder3 != null) {
                            int length2 = spannableStringBuilder3.length();
                            Intrinsics.d(eVar5.c.a);
                            if (length2 == r2.length() - 1) {
                                org.wordpress.aztec.watchers.event.text.b bVar = eVar4.a;
                                Editable editable2 = eVar5.c.a;
                                Intrinsics.d(editable2);
                                if (editable2.charAt(bVar.b) == '\n') {
                                    if (!c.c(bVar)) {
                                        break;
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                break;
        }
        return org.wordpress.aztec.watchers.event.sequence.b.b;
    }
}
