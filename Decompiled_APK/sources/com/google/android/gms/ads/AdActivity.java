package com.google.android.gms.ads;

import android.app.Activity;
import android.content.Intent;
import android.content.res.Configuration;
import android.os.Bundle;
import android.os.RemoteException;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import com.google.android.gms.ads.internal.client.C1586c;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.internal.ads.InterfaceC1672Cb;

/* loaded from: classes2.dex */
public final class AdActivity extends Activity {
    public InterfaceC1672Cb a;

    @Override // android.app.Activity
    public final void onActivityResult(int i, int i2, Intent intent) {
        try {
            InterfaceC1672Cb interfaceC1672Cb = this.a;
            if (interfaceC1672Cb != null) {
                interfaceC1672Cb.m1(i, i2, intent);
            }
        } catch (Exception e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
        super.onActivityResult(i, i2, intent);
    }

    @Override // android.app.Activity
    public final void onBackPressed() {
        try {
            InterfaceC1672Cb interfaceC1672Cb = this.a;
            if (interfaceC1672Cb != null) {
                if (!interfaceC1672Cb.s3()) {
                    return;
                }
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
        super.onBackPressed();
        try {
            InterfaceC1672Cb interfaceC1672Cb2 = this.a;
            if (interfaceC1672Cb2 != null) {
                interfaceC1672Cb2.zzi();
            }
        } catch (RemoteException e2) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e2);
        }
    }

    @Override // android.app.Activity, android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        try {
            InterfaceC1672Cb interfaceC1672Cb = this.a;
            if (interfaceC1672Cb != null) {
                interfaceC1672Cb.v2(new com.google.android.gms.dynamic.b(configuration));
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }

    @Override // android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        com.google.android.gms.ads.internal.util.client.i.d("AdActivity onCreate");
        C1608n c1608n = C1614q.f.b;
        c1608n.getClass();
        C1586c c1586c = new C1586c(c1608n, this);
        Intent intent = getIntent();
        boolean booleanExtra = false;
        if (intent.hasExtra("com.google.android.gms.ads.internal.overlay.useClientJar")) {
            booleanExtra = intent.getBooleanExtra("com.google.android.gms.ads.internal.overlay.useClientJar", false);
        } else {
            com.google.android.gms.ads.internal.util.client.i.e("useClientJar flag not found in activity intent extras.");
        }
        InterfaceC1672Cb interfaceC1672Cb = (InterfaceC1672Cb) c1586c.d(this, booleanExtra);
        this.a = interfaceC1672Cb;
        if (interfaceC1672Cb == null) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", null);
            finish();
            return;
        }
        try {
            interfaceC1672Cb.p2(bundle);
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            finish();
        }
    }

    @Override // android.app.Activity
    public final void onDestroy() {
        com.google.android.gms.ads.internal.util.client.i.d("AdActivity onDestroy");
        try {
            InterfaceC1672Cb interfaceC1672Cb = this.a;
            if (interfaceC1672Cb != null) {
                interfaceC1672Cb.l();
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
        super.onDestroy();
    }

    @Override // android.app.Activity
    public final void onPause() {
        com.google.android.gms.ads.internal.util.client.i.d("AdActivity onPause");
        try {
            InterfaceC1672Cb interfaceC1672Cb = this.a;
            if (interfaceC1672Cb != null) {
                interfaceC1672Cb.v();
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            finish();
        }
        super.onPause();
    }

    @Override // android.app.Activity
    public final void onRequestPermissionsResult(int i, String[] strArr, int[] iArr) {
        try {
            InterfaceC1672Cb interfaceC1672Cb = this.a;
            if (interfaceC1672Cb != null) {
                interfaceC1672Cb.H1(i, strArr, iArr);
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }

    @Override // android.app.Activity
    public final void onRestart() {
        super.onRestart();
        com.google.android.gms.ads.internal.util.client.i.d("AdActivity onRestart");
        try {
            InterfaceC1672Cb interfaceC1672Cb = this.a;
            if (interfaceC1672Cb != null) {
                interfaceC1672Cb.p();
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            finish();
        }
    }

    @Override // android.app.Activity
    public final void onResume() {
        com.google.android.gms.ads.internal.util.client.i.d("AdActivity onResume");
        super.onResume();
        try {
            InterfaceC1672Cb interfaceC1672Cb = this.a;
            if (interfaceC1672Cb != null) {
                interfaceC1672Cb.w();
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            finish();
        }
    }

    @Override // android.app.Activity
    public final void onSaveInstanceState(Bundle bundle) {
        try {
            InterfaceC1672Cb interfaceC1672Cb = this.a;
            if (interfaceC1672Cb != null) {
                interfaceC1672Cb.B2(bundle);
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            finish();
        }
        super.onSaveInstanceState(bundle);
    }

    @Override // android.app.Activity
    public final void onStart() {
        super.onStart();
        com.google.android.gms.ads.internal.util.client.i.d("AdActivity onStart");
        try {
            InterfaceC1672Cb interfaceC1672Cb = this.a;
            if (interfaceC1672Cb != null) {
                interfaceC1672Cb.s();
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            finish();
        }
    }

    @Override // android.app.Activity
    public final void onStop() {
        com.google.android.gms.ads.internal.util.client.i.d("AdActivity onStop");
        try {
            InterfaceC1672Cb interfaceC1672Cb = this.a;
            if (interfaceC1672Cb != null) {
                interfaceC1672Cb.c();
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            finish();
        }
        super.onStop();
    }

    @Override // android.app.Activity
    public final void onUserLeaveHint() {
        super.onUserLeaveHint();
        try {
            InterfaceC1672Cb interfaceC1672Cb = this.a;
            if (interfaceC1672Cb != null) {
                interfaceC1672Cb.d();
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }

    @Override // android.app.Activity
    public final void setContentView(int i) {
        super.setContentView(i);
        InterfaceC1672Cb interfaceC1672Cb = this.a;
        if (interfaceC1672Cb != null) {
            try {
                interfaceC1672Cb.y();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            }
        }
    }

    @Override // android.app.Activity
    public final void setContentView(@NonNull View view) {
        super.setContentView(view);
        InterfaceC1672Cb interfaceC1672Cb = this.a;
        if (interfaceC1672Cb != null) {
            try {
                interfaceC1672Cb.y();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            }
        }
    }

    @Override // android.app.Activity
    public final void setContentView(View view, ViewGroup.LayoutParams layoutParams) {
        super.setContentView(view, layoutParams);
        InterfaceC1672Cb interfaceC1672Cb = this.a;
        if (interfaceC1672Cb != null) {
            try {
                interfaceC1672Cb.y();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            }
        }
    }
}
