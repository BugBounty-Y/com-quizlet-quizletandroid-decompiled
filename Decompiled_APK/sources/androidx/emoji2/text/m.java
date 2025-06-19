package androidx.emoji2.text;

import android.content.Context;
import android.net.ConnectivityManager;
import androidx.camera.camera2.internal.RunnableC0130g;
import com.google.android.gms.internal.mlkit_vision_barcode.X6;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes.dex */
public final class m implements i, com.bumptech.glide.util.g {
    public final Context a;

    public m(Context context, int i) {
        switch (i) {
            case 1:
                this.a = context;
                break;
            default:
                this.a = context.getApplicationContext();
                break;
        }
    }

    @Override // androidx.emoji2.text.i
    public void a(X6 x6) {
        ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(0, 1, 15L, TimeUnit.SECONDS, new LinkedBlockingDeque(), new ThreadFactoryC1119a("EmojiCompatInitializer"));
        threadPoolExecutor.allowCoreThreadTimeOut(true);
        threadPoolExecutor.execute(new RunnableC0130g(this, x6, threadPoolExecutor, 10));
    }

    @Override // com.bumptech.glide.util.g
    public Object get() {
        return (ConnectivityManager) this.a.getSystemService("connectivity");
    }
}
