package androidx.work.impl.constraints.controllers;

import android.os.Build;
import androidx.work.A;
import androidx.work.impl.constraints.i;
import androidx.work.impl.model.q;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d extends c {
    public final /* synthetic */ int b;
    public final int c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(androidx.work.impl.constraints.trackers.a tracker) {
        super(tracker);
        this.b = 0;
        Intrinsics.checkNotNullParameter(tracker, "tracker");
        this.c = 6;
    }

    @Override // androidx.work.impl.constraints.controllers.e
    public final boolean b(q workSpec) {
        switch (this.b) {
            case 0:
                Intrinsics.checkNotNullParameter(workSpec, "workSpec");
                return workSpec.j.c;
            case 1:
                Intrinsics.checkNotNullParameter(workSpec, "workSpec");
                return workSpec.j.e;
            case 2:
                Intrinsics.checkNotNullParameter(workSpec, "workSpec");
                return workSpec.j.a == A.b;
            case 3:
                Intrinsics.checkNotNullParameter(workSpec, "workSpec");
                A a = workSpec.j.a;
                return a == A.c || (Build.VERSION.SDK_INT >= 30 && a == A.f);
            default:
                Intrinsics.checkNotNullParameter(workSpec, "workSpec");
                return workSpec.j.f;
        }
    }

    @Override // androidx.work.impl.constraints.controllers.c
    public final int d() {
        switch (this.b) {
        }
        return this.c;
    }

    @Override // androidx.work.impl.constraints.controllers.c
    public final boolean e(Object obj) {
        switch (this.b) {
            case 2:
                i value = (i) obj;
                Intrinsics.checkNotNullParameter(value, "value");
                if (!value.a || !value.b) {
                }
                break;
            case 3:
                i value2 = (i) obj;
                Intrinsics.checkNotNullParameter(value2, "value");
                if (!value2.a || value2.c) {
                }
                break;
        }
        return !((Boolean) obj).booleanValue();
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(androidx.work.impl.constraints.trackers.a tracker, byte b) {
        super(tracker);
        this.b = 1;
        Intrinsics.checkNotNullParameter(tracker, "tracker");
        this.c = 5;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(androidx.work.impl.constraints.trackers.a tracker, char c) {
        super(tracker);
        this.b = 4;
        Intrinsics.checkNotNullParameter(tracker, "tracker");
        this.c = 9;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(androidx.work.impl.constraints.trackers.g tracker, int i) {
        super(tracker);
        this.b = i;
        switch (i) {
            case 3:
                Intrinsics.checkNotNullParameter(tracker, "tracker");
                super(tracker);
                this.c = 7;
                break;
            default:
                Intrinsics.checkNotNullParameter(tracker, "tracker");
                this.c = 7;
                break;
        }
    }
}
