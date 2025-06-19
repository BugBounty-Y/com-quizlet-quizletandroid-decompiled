package com.quizlet.quizletandroid.ui.joincontenttofolder;

import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.model.C4123e0;
import com.quizlet.data.model.F;
import com.quizlet.remote.model.classset.RemoteClassSet;
import com.quizlet.remote.model.folderset.RemoteFolderSet;
import com.quizlet.remote.model.search.RemoteSearchSocialSignalForSets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Pair;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j implements io.reactivex.rxjava3.functions.b, com.quizlet.remote.mapper.base.b, kotlin.coroutines.l {
    public final /* synthetic */ int a;

    public /* synthetic */ j(int i) {
        this.a = i;
    }

    public static void b(org.koin.core.logger.a level, String msg) {
        Intrinsics.checkNotNullParameter(level, "level");
        Intrinsics.checkNotNullParameter(msg, "msg");
    }

    public static F i(RemoteClassSet remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        Long l = remote.a;
        Long l2 = remote.d;
        long jLongValue = l2 != null ? l2.longValue() : 0L;
        Boolean bool = remote.f;
        boolean zBooleanValue = bool != null ? bool.booleanValue() : false;
        Long l3 = remote.g;
        long jLongValue2 = l3 != null ? l3.longValue() : 0L;
        Long l4 = remote.h;
        long jLongValue3 = l4 != null ? l4.longValue() : 0L;
        Boolean bool2 = remote.k;
        return new F(l, remote.c, remote.b, jLongValue, remote.e, zBooleanValue, jLongValue2, remote.j, remote.i, jLongValue3, bool2 != null ? bool2.booleanValue() : false);
    }

    public static com.quizlet.data.model.search.d j(RemoteSearchSocialSignalForSets remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        long j = remote.g;
        return new com.quizlet.data.model.search.d(remote.a, remote.b, remote.c, remote.d, remote.e, remote.f, j);
    }

    public void a(String msg) {
        Intrinsics.checkNotNullParameter(msg, "msg");
        g(org.koin.core.logger.a.a, msg);
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object t1, Object t2) {
        Intrinsics.checkNotNullExpressionValue(t1, "t1");
        Intrinsics.checkNotNullExpressionValue(t2, "t2");
        return new Pair((List) t1, (List) t2);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public Object c(Object obj) {
        switch (this.a) {
            case 1:
                return i((RemoteClassSet) obj);
            case 2:
                RemoteFolderSet remote = (RemoteFolderSet) obj;
                Intrinsics.checkNotNullParameter(remote, "remote");
                Long l = remote.a;
                Long l2 = remote.d;
                long jLongValue = l2 != null ? l2.longValue() : 0L;
                Long l3 = remote.g;
                return new C4123e0(l, remote.b, remote.c, jLongValue, remote.e, remote.f, l3 != null ? l3.longValue() : 0L, remote.h);
            default:
                return j((RemoteSearchSocialSignalForSets) obj);
        }
    }

    public void d(String msg) {
        Intrinsics.checkNotNullParameter(msg, "msg");
        g(org.koin.core.logger.a.b, msg);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List remotes) {
        switch (this.a) {
            case 1:
                return T.f(this, remotes);
            case 2:
                return T.f(this, remotes);
            default:
                Intrinsics.checkNotNullParameter(remotes, "remotes");
                ArrayList arrayList = new ArrayList(C.q(remotes, 10));
                Iterator it2 = remotes.iterator();
                while (it2.hasNext()) {
                    arrayList.add(j((RemoteSearchSocialSignalForSets) it2.next()));
                }
                return arrayList;
        }
    }

    public boolean f(org.koin.core.logger.a lvl) {
        Intrinsics.checkNotNullParameter(lvl, "lvl");
        return org.koin.core.logger.a.e.compareTo(lvl) <= 0;
    }

    public void g(org.koin.core.logger.a lvl, String msg) {
        Intrinsics.checkNotNullParameter(lvl, "lvl");
        Intrinsics.checkNotNullParameter(msg, "msg");
        if (f(lvl)) {
            b(lvl, msg);
        }
    }

    @Override // com.quizlet.remote.mapper.base.c
    public Object h(Object obj) {
        switch (this.a) {
            case 1:
                F data = (F) obj;
                Intrinsics.checkNotNullParameter(data, "data");
                Long l = data.a;
                Long lValueOf = Long.valueOf(data.d);
                Boolean boolValueOf = Boolean.valueOf(data.f);
                Long lValueOf2 = Long.valueOf(data.g);
                Long lValueOf3 = Long.valueOf(data.j);
                Boolean boolValueOf2 = Boolean.valueOf(data.k);
                return new RemoteClassSet(l, data.c, data.b, lValueOf, data.e, boolValueOf, lValueOf2, lValueOf3, data.i, data.h, boolValueOf2);
            case 2:
                C4123e0 data2 = (C4123e0) obj;
                Intrinsics.checkNotNullParameter(data2, "data");
                Long l2 = data2.a;
                Long lValueOf4 = Long.valueOf(data2.d);
                Long lValueOf5 = Long.valueOf(data2.g);
                return new RemoteFolderSet(l2, data2.b, data2.c, lValueOf4, data2.e, data2.f, lValueOf5, data2.h);
            default:
                com.quizlet.data.model.search.d data3 = (com.quizlet.data.model.search.d) obj;
                Intrinsics.checkNotNullParameter(data3, "data");
                return new RemoteSearchSocialSignalForSets(data3.b, data3.c, data3.d, data3.e, data3.f, data3.g, data3.a);
        }
    }
}
