package kotlin.collections;

import java.io.BufferedReader;
import java.util.Iterator;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.sequences.Sequence;

/* renamed from: kotlin.collections.w, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4931w implements Sequence {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ C4931w(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    /* JADX WARN: Type inference failed for: r0v10, types: [kotlin.coroutines.jvm.internal.h, kotlin.jvm.functions.Function2] */
    @Override // kotlin.sequences.Sequence
    public final Iterator iterator() {
        switch (this.a) {
            case 0:
                return kotlin.jvm.internal.O.f((Object[]) this.b);
            case 1:
                return ((Iterable) this.b).iterator();
            case 2:
                return new kotlin.io.l(this);
            case 3:
                return new kotlin.io.e(((Iterable) ((C4931w) this.b).b).iterator());
            case 4:
                return kotlin.sequences.j.a((kotlin.coroutines.jvm.internal.h) this.b);
            default:
                return (Iterator) this.b;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public C4931w(Function2 function2) {
        this.a = 4;
        this.b = (kotlin.coroutines.jvm.internal.h) function2;
    }

    public C4931w(BufferedReader reader) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(reader, "reader");
        this.b = reader;
    }

    public C4931w(C4931w source) {
        this.a = 3;
        assistantMode.tasks.sequencing.a keySelector = assistantMode.tasks.sequencing.a.a;
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(keySelector, "keySelector");
        this.b = source;
    }
}
