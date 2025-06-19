package androidx.navigation;

import android.app.Activity;
import android.content.Context;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@V("activity")
@Metadata
/* renamed from: androidx.navigation.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public class C1267c extends W {
    public final Activity c;

    public C1267c(@NotNull Context context) {
        Object next;
        Intrinsics.checkNotNullParameter(context, "context");
        Iterator it2 = kotlin.sequences.n.c(new C1265a(0), context).iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            } else {
                next = it2.next();
                if (((Context) next) instanceof Activity) {
                    break;
                }
            }
        }
        this.c = (Activity) next;
    }

    @Override // androidx.navigation.W
    public final B a() {
        Intrinsics.checkNotNullParameter(this, "activityNavigator");
        return new C1266b(this);
    }

    @Override // androidx.navigation.W
    public final B c(B b) {
        C1266b destination = (C1266b) b;
        Intrinsics.checkNotNullParameter(destination, "destination");
        throw new IllegalStateException(android.support.v4.media.session.a.r(new StringBuilder("Destination "), destination.b.c, " does not have an Intent set.").toString());
    }

    @Override // androidx.navigation.W
    public final boolean g() {
        Activity activity = this.c;
        if (activity == null) {
            return false;
        }
        activity.finish();
        return true;
    }
}
