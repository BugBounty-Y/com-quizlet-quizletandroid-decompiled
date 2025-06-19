package com.google.android.gms.oss.licenses;

import android.content.Intent;
import android.content.res.Resources;
import android.os.Bundle;
import android.os.Looper;
import android.util.Log;
import android.view.MenuItem;
import android.widget.ListView;
import androidx.appcompat.app.AbstractActivityC0055k;
import androidx.collection.W;
import androidx.collection.r;
import androidx.loader.app.f;
import androidx.loader.app.g;
import androidx.work.impl.model.v;
import com.google.android.gms.tasks.m;
import com.quizlet.quizletandroid.R;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class OssLicensesMenuActivity extends AbstractActivityC0055k implements androidx.loader.app.a {
    public static String h;
    public ListView c;
    public e d;
    public boolean e;
    public v f;
    public m g;

    public static boolean x(OssLicensesMenuActivity ossLicensesMenuActivity, String str) throws IOException {
        InputStream inputStreamOpenRawResource = null;
        try {
            Resources resources = ossLicensesMenuActivity.getResources();
            inputStreamOpenRawResource = resources.openRawResource(resources.getIdentifier(str, "raw", resources.getResourcePackageName(R.id.license_list)));
            boolean z = inputStreamOpenRawResource.available() > 0;
            try {
                inputStreamOpenRawResource.close();
            } catch (IOException unused) {
            }
            return z;
        } catch (Resources.NotFoundException | IOException unused2) {
            if (inputStreamOpenRawResource != null) {
                try {
                    inputStreamOpenRawResource.close();
                } catch (IOException unused3) {
                }
            }
            return false;
        } catch (Throwable th) {
            if (inputStreamOpenRawResource != null) {
                try {
                    inputStreamOpenRawResource.close();
                } catch (IOException unused4) {
                }
            }
            throw th;
        }
    }

    @Override // androidx.loader.app.a
    public final void g() {
        this.d.clear();
        this.d.notifyDataSetChanged();
    }

    @Override // androidx.loader.app.a
    public final void i(Object obj) {
        this.d.clear();
        this.d.addAll((List) obj);
        this.d.notifyDataSetChanged();
    }

    @Override // androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        com.quizlet.data.interactor.school.b.q(this);
        this.e = x(this, "third_party_licenses") && x(this, "third_party_license_metadata");
        if (h == null) {
            Intent intent = getIntent();
            if (intent.hasExtra("title")) {
                h = intent.getStringExtra("title");
                Log.w("OssLicensesMenuActivity", "The intent based title is deprecated. Use OssLicensesMenuActivity.setActivityTitle(title) instead.");
            }
        }
        String str = h;
        if (str != null) {
            setTitle(str);
        }
        if (r() != null) {
            r().s(true);
        }
        if (!this.e) {
            setContentView(R.layout.license_menu_activity_no_licenses);
            return;
        }
        this.g = ((c) com.quizlet.data.interactor.school.b.q(this).b).c(0, new b(getPackageName(), 1));
        getSupportLoaderManager().a(54321, this);
        this.g.addOnCompleteListener(new com.google.android.gms.internal.instantapps.a(this, 28));
    }

    @Override // androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        f fVar = ((g) getSupportLoaderManager()).b;
        if (fVar.c) {
            throw new IllegalStateException("Called while creating a loader");
        }
        if (Looper.getMainLooper() != Looper.myLooper()) {
            throw new IllegalStateException("destroyLoader must be called on the main thread");
        }
        androidx.loader.app.c cVar = (androidx.loader.app.c) fVar.b.d(54321);
        if (cVar != null) {
            cVar.m();
            W w = fVar.b;
            w.getClass();
            Intrinsics.checkNotNullParameter(w, "<this>");
            int iA = androidx.collection.internal.a.a(w.d, 54321, w.b);
            if (iA >= 0) {
                Object[] objArr = w.c;
                Object obj = objArr[iA];
                Object obj2 = r.b;
                if (obj != obj2) {
                    objArr[iA] = obj2;
                    w.a = true;
                }
            }
        }
        super.onDestroy();
    }

    @Override // android.app.Activity
    public final boolean onOptionsItemSelected(MenuItem menuItem) {
        if (menuItem.getItemId() != 16908332) {
            return super.onOptionsItemSelected(menuItem);
        }
        finish();
        return true;
    }

    @Override // androidx.loader.app.a
    public final androidx.loader.content.c p() {
        if (this.e) {
            return new com.google.android.gms.auth.api.signin.internal.c(this, com.quizlet.data.interactor.school.b.q(this));
        }
        return null;
    }
}
