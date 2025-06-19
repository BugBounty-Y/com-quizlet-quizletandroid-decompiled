package com.braze.managers;

import java.util.List;
import java.util.ListIterator;
import java.util.NoSuchElementException;
import java.util.UUID;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlin.text.StringsKt__StringsKt;

/* loaded from: classes.dex */
public final /* synthetic */ class U implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ List b;

    public /* synthetic */ U(com.quizlet.quizletandroid.deeplinks.a aVar, List list, int i) {
        this.a = i;
        this.b = list;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return z.a(this.b);
            case 1:
                return com.braze.models.outgoing.e.a(this.b);
            case 2:
                return com.braze.triggers.managers.f.b(this.b);
            case 3:
                return io.reactivex.rxjava3.core.p.f(this.b);
            case 4:
                io.reactivex.rxjava3.internal.operators.flowable.b bVarF = io.reactivex.rxjava3.core.p.f(this.b);
                Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
                return bVarF;
            case 5:
                return Integer.valueOf(this.b.size());
            case 6:
                String string = UUID.fromString(kotlin.text.I.D(36, (String) this.b.get(2))).toString();
                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                return string;
            case 7:
                List listSplit$default = StringsKt__StringsKt.split$default((CharSequence) this.b.get(2), new String[]{"-"}, false, 0, 6, null);
                ListIterator listIterator = listSplit$default.listIterator(listSplit$default.size());
                while (listIterator.hasPrevious()) {
                    String str = (String) listIterator.previous();
                    if (!StringsKt.O(str)) {
                        return str;
                    }
                }
                throw new NoSuchElementException("List contains no element matching the predicate.");
            case 8:
                String string2 = UUID.fromString(kotlin.text.I.D(36, (String) this.b.get(3))).toString();
                Intrinsics.checkNotNullExpressionValue(string2, "toString(...)");
                return string2;
            case 9:
                return ((kotlin.reflect.o) this.b.get(0)).d();
            default:
                return ((kotlin.reflect.o) this.b.get(0)).d();
        }
    }

    public /* synthetic */ U(List list, int i) {
        this.a = i;
        this.b = list;
    }
}
