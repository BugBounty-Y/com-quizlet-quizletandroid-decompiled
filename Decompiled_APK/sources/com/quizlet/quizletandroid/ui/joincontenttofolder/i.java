package com.quizlet.quizletandroid.ui.joincontenttofolder;

import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.model.E;
import com.quizlet.data.model.F0;
import com.quizlet.generated.enums.EnumC4478e1;
import com.quizlet.generated.enums.EnumC4526v;
import com.quizlet.remote.model.classmembership.RemoteClassMembership;
import com.quizlet.remote.model.folder.RemoteFolder;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlin.text.StringsKt;
import okio.x;

/* loaded from: classes3.dex */
public final class i implements io.reactivex.rxjava3.functions.b, com.quizlet.remote.mapper.base.b, com.quizlet.remote.mapper.base.c, com.quizlet.remote.mapper.base.a, androidx.lifecycle.viewmodel.b {
    public final /* synthetic */ int a;

    public /* synthetic */ i(int i) {
        this.a = i;
    }

    public static final boolean a(x xVar) {
        x xVar2 = okio.internal.g.f;
        return !D.k(xVar.b(), ".class", true);
    }

    public static x d(x xVar, x base) {
        Intrinsics.checkNotNullParameter(xVar, "<this>");
        Intrinsics.checkNotNullParameter(base, "base");
        return okio.internal.g.f.e(D.p(StringsKt.T(xVar.a.s(), base.a.s()), '\\', '/'));
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object t1, Object t2) {
        Intrinsics.checkNotNullExpressionValue(t1, "t1");
        Intrinsics.checkNotNullExpressionValue(t2, "t2");
        return new Pair((List) t1, (List) t2);
    }

    public Object b(Object obj) {
        Object value = (Enum) obj;
        Intrinsics.checkNotNullParameter(value, "value");
        return Long.valueOf(((serialization.b) value).getValue().intValue());
    }

    @Override // com.quizlet.remote.mapper.base.a
    public Object c(Object obj) {
        switch (this.a) {
            case 1:
                RemoteClassMembership remote = (RemoteClassMembership) obj;
                Intrinsics.checkNotNullParameter(remote, "remote");
                long j = remote.a;
                EnumC4526v.Companion.getClass();
                for (EnumC4526v enumC4526v : EnumC4526v.values()) {
                    if (enumC4526v.a() == remote.d) {
                        return new E(j, remote.b, remote.c, enumC4526v, remote.e, remote.f, remote.g);
                    }
                }
                throw new NoSuchElementException("Array contains no element matching the predicate.");
            default:
                String value = (String) obj;
                Intrinsics.checkNotNullParameter(value, "remote");
                EnumC4478e1.Companion.getClass();
                Intrinsics.checkNotNullParameter(value, "value");
                for (EnumC4478e1 enumC4478e1 : EnumC4478e1.values()) {
                    if (Intrinsics.b(enumC4478e1.a(), value)) {
                        return enumC4478e1;
                    }
                }
                throw new NoSuchElementException("Array contains no element matching the predicate.");
        }
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        switch (this.a) {
            case 1:
                return T.f(this, list);
            default:
                return S.f(this, list);
        }
    }

    @Override // com.quizlet.remote.mapper.base.c
    public Object h(Object obj) {
        switch (this.a) {
            case 1:
                E data = (E) obj;
                Intrinsics.checkNotNullParameter(data, "data");
                return new RemoteClassMembership(data.a, data.b, data.c, data.d.a(), data.e, data.f, data.g);
            default:
                F0 data2 = (F0) obj;
                Intrinsics.checkNotNullParameter(data2, "data");
                return new RemoteFolder(null, null, Long.valueOf(data2.a), data2.b, data2.c, 0L, Boolean.FALSE, null, false, Long.valueOf(com.quizlet.time.b.a()), 0L, true, null, null, null, null, null, null, null, null, 1044480, null);
        }
    }

    public i(Enum[] enumValues) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(enumValues, "enumValues");
    }
}
