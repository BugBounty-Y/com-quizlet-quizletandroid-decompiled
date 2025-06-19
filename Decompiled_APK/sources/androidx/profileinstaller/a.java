package androidx.profileinstaller;

import android.content.res.AssetManager;
import android.os.Build;
import androidx.activity.RunnableC0043o;
import androidx.constraintlayout.motion.widget.n;
import androidx.navigation.internal.m;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3633h4;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public final class a {
    public final /* synthetic */ int a;
    public String b;
    public boolean c;
    public Object d;
    public Object e;
    public Object f;
    public Object g;
    public Object h;
    public Object i;

    public FileInputStream a(AssetManager assetManager, String str) {
        try {
            return assetManager.openFd(str).createInputStream();
        } catch (FileNotFoundException e) {
            String message = e.getMessage();
            if (message == null) {
                return null;
            }
            message.contains("compressed");
            return null;
        }
    }

    public void b(int i, Serializable serializable) {
        ((Executor) this.d).execute(new RunnableC0043o(this, i, serializable, 6));
    }

    public String toString() {
        switch (this.a) {
            case 2:
                StringBuilder sb = new StringBuilder("OTConsentPreferencesUIProperty{show='");
                sb.append(this.b);
                sb.append("', backgroundColor='null', titleTextProperty=");
                AbstractC3633h4.a((m) this.f, sb, ", descriptionTextProperty=");
                AbstractC3633h4.a((m) this.g, sb, ", showOTLogo=");
                sb.append(this.c);
                sb.append(", saveChoicesButtonProperty=");
                sb.append(((n) this.h).toString());
                sb.append(", otConsentPreferencesPurposeModelHashSet=");
                sb.append((ArrayList) this.i);
                sb.append('}');
                return sb.toString();
            default:
                return super.toString();
        }
    }

    public a(AssetManager assetManager, Executor executor, c cVar, String str, File file) {
        byte[] bArr;
        this.a = 0;
        this.c = false;
        this.d = executor;
        this.e = cVar;
        this.b = str;
        this.h = file;
        int i = Build.VERSION.SDK_INT;
        if (i < 31) {
            switch (i) {
                case EventType.CDN /* 26 */:
                    bArr = d.g;
                    break;
                case 27:
                    bArr = d.f;
                    break;
                case 28:
                case 29:
                case 30:
                    bArr = d.e;
                    break;
                default:
                    bArr = null;
                    break;
            }
        } else {
            bArr = d.d;
        }
        this.f = bArr;
    }
}
