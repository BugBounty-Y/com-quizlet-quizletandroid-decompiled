package com.pubmatic.sdk.video.vastparser;

import android.os.Handler;
import android.os.Looper;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.h;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.network.g;
import com.pubmatic.sdk.common.utility.o;
import com.pubmatic.sdk.video.vastmodels.i;
import com.pubmatic.sdk.video.vastmodels.j;
import java.util.List;

/* loaded from: classes2.dex */
public class a {
    private final com.pubmatic.sdk.video.vastparser.b a;
    private final int b;

    @NonNull
    private final g d;
    private int e = 5000;

    @NonNull
    private final Handler c = new Handler(Looper.getMainLooper());

    /* renamed from: com.pubmatic.sdk.video.vastparser.a$a, reason: collision with other inner class name */
    public class RunnableC0021a implements Runnable {
        final /* synthetic */ String a;

        public RunnableC0021a(String str) {
            this.a = str;
        }

        @Override // java.lang.Runnable
        public void run() {
            a aVar = a.this;
            aVar.a(this.a, aVar.b, (j) null);
        }
    }

    public class b implements com.pubmatic.sdk.common.network.d {
        final /* synthetic */ i a;
        final /* synthetic */ int b;

        public b(i iVar, int i) {
            this.a = iVar;
            this.b = i;
        }

        @Override // com.pubmatic.sdk.common.network.d
        /* renamed from: a, reason: merged with bridge method [inline-methods] */
        public void onSuccess(String str) {
            if (str == null || this.a.getAds() == null) {
                POBLog.debug("POBVastParser", "Network response is null", new Object[0]);
                a.this.a(this.a, 303, "Empty vast ad received.");
            } else if (a.this.a(str, this.b - 1, this.a.getAds().get(0)) == null) {
                a.this.a(this.a, 100, "Failed to parse vast response.");
            }
        }

        @Override // com.pubmatic.sdk.common.network.d
        public void onFailure(@NonNull h hVar) {
            a aVar = a.this;
            aVar.a(this.a, aVar.a(hVar), hVar.getErrorMessage());
        }
    }

    public class c implements Runnable {
        final /* synthetic */ i a;
        final /* synthetic */ int b;
        final /* synthetic */ String c;

        public c(i iVar, int i, String str) {
            this.a = iVar;
            this.b = i;
            this.c = str;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (a.this.a != null) {
                a.this.a.onFailure(this.a, new com.pubmatic.sdk.video.a(this.b, this.c));
            }
        }
    }

    public class d implements Runnable {
        final /* synthetic */ i a;

        public d(i iVar) {
            this.a = iVar;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (a.this.a != null) {
                a.this.a.onSuccess(this.a);
            }
        }
    }

    public a(@NonNull g gVar, int i, com.pubmatic.sdk.video.vastparser.b bVar) {
        this.d = gVar;
        this.a = bVar;
        this.b = i;
    }

    public void parse(@NonNull String str) {
        o.runOnBackgroundThread(new RunnableC0021a(str));
    }

    public void setWrapperTimeout(int i) {
        this.e = i;
    }

    private boolean b(i iVar) {
        return (iVar == null || iVar.getAds() == null || iVar.getAds().isEmpty() || iVar.getAds().get(0).getAdType() != j.b.INLINE) ? false : true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public i a(@NonNull String str, int i, j jVar) {
        i iVar = (i) com.pubmatic.sdk.video.xmlserialiser.c.parse(str, i.class);
        if (iVar != null) {
            if (iVar.getAds() != null && !iVar.getAds().isEmpty()) {
                iVar.getAds().get(0).setWrapper(jVar);
            }
            if (iVar.getVersion() != null && !a(iVar.getVersion())) {
                a(iVar, 102, "Received vast version is unsupported.");
                return iVar;
            }
            if (b(iVar)) {
                a(iVar);
                return iVar;
            }
            if (i == 0) {
                a(iVar, 302, "Maximum wrapper attempts reached.");
                return iVar;
            }
            List<j> ads = iVar.getAds();
            if (ads != null && !ads.isEmpty() && ads.get(0).getAdType() != j.b.NO_ADS) {
                String vASTAdTagURI = ads.get(0).getVASTAdTagURI();
                if (vASTAdTagURI != null && !vASTAdTagURI.isEmpty()) {
                    com.pubmatic.sdk.common.network.a aVar = new com.pubmatic.sdk.common.network.a();
                    aVar.setUrl(vASTAdTagURI);
                    aVar.setRequestTag("POBVastParser");
                    aVar.setTimeout(this.e);
                    this.d.sendRequest(aVar, new b(iVar, i));
                    return iVar;
                }
                a(iVar, 101, "Ad tag URI is missing in wrapper vast response.");
                return iVar;
            }
            a(iVar, 303, "Empty vast ad received.");
            return iVar;
        }
        if (i == this.b) {
            a((i) null, 100, "Failed to parse vast response.");
        }
        return iVar;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(i iVar, int i, @NonNull String str) {
        this.c.post(new c(iVar, i, str));
    }

    private void a(@NonNull i iVar) {
        this.c.post(new d(iVar));
    }

    private boolean a(String str) {
        if (str != null) {
            try {
                if (Integer.parseInt(str.split("\\.")[0]) >= 2) {
                    return true;
                }
            } catch (Exception unused) {
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int a(h hVar) {
        return (hVar == null || hVar.getErrorCode() != 1005) ? 300 : 301;
    }
}
