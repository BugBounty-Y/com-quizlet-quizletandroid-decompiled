package com.google.android.gms.auth.api.signin.internal;

import android.content.Context;
import android.content.res.Resources;
import android.util.Log;
import com.google.android.gms.common.api.internal.y;
import com.google.android.gms.internal.mlkit_vision_common.R3;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.internal.oss_licenses.zze;
import com.google.android.gms.oss.licenses.OssLicensesMenuActivity;
import com.google.android.gms.tasks.m;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class c extends androidx.loader.content.b {
    public final /* synthetic */ int k = 0;
    public Object l;
    public final Object m;

    public c(Context context, Set set) {
        super(context);
        this.l = new Semaphore(0);
        this.m = set;
    }

    @Override // androidx.loader.content.c
    public /* synthetic */ void a(Object obj) {
        switch (this.k) {
            case 1:
                List list = (List) obj;
                this.l = list;
                super.a(list);
                break;
            default:
                super.a(obj);
                break;
        }
    }

    @Override // androidx.loader.content.c
    public final void d() {
        switch (this.k) {
            case 0:
                ((Semaphore) this.l).drainPermits();
                h();
                break;
            default:
                List list = (List) this.l;
                if (list == null) {
                    h();
                    break;
                } else {
                    super.a(list);
                    break;
                }
        }
    }

    @Override // androidx.loader.content.c
    public void e() {
        switch (this.k) {
            case 1:
                c();
                break;
        }
    }

    @Override // androidx.loader.content.b
    public final Object g() throws InterruptedException {
        switch (this.k) {
            case 0:
                Iterator it2 = ((Set) this.m).iterator();
                if (it2.hasNext()) {
                    ((com.google.android.gms.common.api.h) it2.next()).getClass();
                    throw new UnsupportedOperationException();
                }
                try {
                    ((Semaphore) this.l).tryAcquire(0, 5L, TimeUnit.SECONDS);
                    return null;
                } catch (InterruptedException e) {
                    Log.i("GACSignInLoader", "Unexpected InterruptedException", e);
                    Thread.currentThread().interrupt();
                    return null;
                }
            default:
                Resources resources = this.c.getApplicationContext().getApplicationContext().getResources();
                String[] strArrSplit = R3.b(resources.openRawResource(resources.getIdentifier("third_party_license_metadata", "raw", resources.getResourcePackageName(R.raw.keep_third_party_licenses))), 0L, -1).split("\n");
                ArrayList arrayList = new ArrayList(strArrSplit.length);
                for (String str : strArrSplit) {
                    int iIndexOf = str.indexOf(32);
                    String[] strArrSplit2 = str.substring(0, iIndexOf).split(":");
                    if (strArrSplit2.length != 2 || iIndexOf <= 0) {
                        throw new IllegalStateException("Invalid license meta-data line:\n".concat(str));
                    }
                    arrayList.add(new zze(Integer.parseInt(strArrSplit2[1]), Long.parseLong(strArrSplit2[0]), str.substring(iIndexOf + 1)));
                }
                Collections.sort(arrayList);
                m mVarC = ((com.google.android.gms.oss.licenses.c) ((com.quizlet.data.interactor.school.b) this.m).b).c(0, new y(arrayList, 2));
                try {
                    S3.e(mVarC);
                    return mVarC.l() ? (List) mVarC.h() : arrayList;
                } catch (InterruptedException | ExecutionException e2) {
                    Log.w("OssLicensesLoader", "Error getting license list from service: ".concat(String.valueOf(e2.getMessage())));
                    return arrayList;
                }
        }
    }

    public c(OssLicensesMenuActivity ossLicensesMenuActivity, com.quizlet.data.interactor.school.b bVar) {
        super(ossLicensesMenuActivity.getApplicationContext());
        this.m = bVar;
    }
}
