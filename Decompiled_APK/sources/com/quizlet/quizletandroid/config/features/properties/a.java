package com.quizlet.quizletandroid.config.features.properties;

import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.DBGroupMembership;
import com.quizlet.db.data.models.wrappers.LoggedInUserStatus;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.functions.i;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h, io.reactivex.rxjava3.functions.b, i {
    public static final a b = new a(0);
    public static final a c = new a(1);
    public static final a d = new a(2);
    public static final a e = new a(3);
    public static final a f = new a(4);
    public static final a g = new a(5);
    public static final a h = new a(6);
    public static final a i = new a(7);
    public static final a j = new a(8);
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i2) {
        this.a = i2;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 0:
                DBGroupMembership s = (DBGroupMembership) obj;
                Intrinsics.checkNotNullParameter(s, "s");
                return Boolean.valueOf(s.isAdmin());
            case 1:
                DBGroup s2 = (DBGroup) obj;
                Intrinsics.checkNotNullParameter(s2, "s");
                return Boolean.valueOf(s2.getAdminOnly());
            case 2:
            case 4:
            case 6:
            default:
                LoggedInUserStatus s3 = (LoggedInUserStatus) obj;
                Intrinsics.checkNotNullParameter(s3, "s");
                return Boolean.valueOf(!s3.isLoggedIn());
            case 3:
                DBGroupMembership s4 = (DBGroupMembership) obj;
                Intrinsics.checkNotNullParameter(s4, "s");
                return Boolean.valueOf(s4.isInvolved());
            case 5:
                List l = (List) obj;
                Intrinsics.checkNotNullParameter(l, "l");
                return (DBGroup) CollectionsKt.L(l);
            case 7:
                List l2 = (List) obj;
                Intrinsics.checkNotNullParameter(l2, "l");
                return (DBGroupMembership) CollectionsKt.L(l2);
        }
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        switch (this.a) {
            case 4:
                List l = (List) obj;
                Intrinsics.checkNotNullParameter(l, "l");
                return !l.isEmpty();
            default:
                List l2 = (List) obj;
                Intrinsics.checkNotNullParameter(l2, "l");
                return !l2.isEmpty();
        }
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object obj, Object obj2) {
        DBGroup group = (DBGroup) obj;
        Long userId = (Long) obj2;
        Intrinsics.checkNotNullParameter(group, "group");
        Intrinsics.checkNotNullParameter(userId, "userId");
        return Boolean.valueOf(group.getCreatorId() == userId.longValue());
    }
}
