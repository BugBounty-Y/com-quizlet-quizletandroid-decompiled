package com.pubmatic.sdk.common.utility;

import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.SystemClock;
import androidx.annotation.NonNull;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public abstract class d {
    private final long a;
    private final long b;
    private long c;
    private long d;
    private final Handler e;
    private b f = b.DEFAULT;

    public class a extends Handler {
        public a(@NonNull Looper looper) {
            super(looper);
        }

        @Override // android.os.Handler
        public void handleMessage(@NonNull Message message) {
            synchronized (d.this) {
                try {
                    if (d.this.f != b.PAUSE) {
                        long j = d.this.c;
                        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
                        long seconds = j - timeUnit.toSeconds(SystemClock.elapsedRealtime());
                        if (seconds <= 0) {
                            b bVar = d.this.f;
                            b bVar2 = b.FINISH;
                            if (bVar != bVar2) {
                                d.this.onFinish();
                                d.this.f = bVar2;
                            }
                        } else if (seconds < d.this.b) {
                            sendMessageDelayed(obtainMessage(1), TimeUnit.SECONDS.toMillis(seconds));
                        } else {
                            long seconds2 = timeUnit.toSeconds(SystemClock.elapsedRealtime());
                            d.this.onTick(seconds);
                            long seconds3 = (seconds2 + d.this.b) - timeUnit.toSeconds(SystemClock.elapsedRealtime());
                            while (seconds3 < 0) {
                                seconds3 += d.this.b;
                            }
                            if (d.this.f != b.CANCEL && d.this.f != b.FINISH) {
                                sendMessageDelayed(obtainMessage(1), TimeUnit.SECONDS.toMillis(seconds3));
                            }
                        }
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    public enum b {
        DEFAULT,
        START,
        PAUSE,
        CANCEL,
        FINISH
    }

    public d(long j, long j2, @NonNull Looper looper) {
        this.a = j;
        this.b = j2;
        this.e = new a(looper);
    }

    public final void cancel() {
        this.e.removeMessages(1);
        this.f = b.CANCEL;
    }

    public abstract void onFinish();

    public abstract void onTick(long j);

    public long pause() {
        if (this.f == b.START) {
            this.d = this.c - TimeUnit.MILLISECONDS.toSeconds(SystemClock.elapsedRealtime());
            this.f = b.PAUSE;
        }
        return this.d;
    }

    public long resume() {
        if (this.f == b.PAUSE) {
            this.c = TimeUnit.MILLISECONDS.toSeconds(SystemClock.elapsedRealtime()) + this.d;
            this.f = b.START;
            Handler handler = this.e;
            handler.sendMessage(handler.obtainMessage(1));
        }
        return this.d;
    }

    public final synchronized d start() {
        if (this.a <= 0) {
            onFinish();
            this.f = b.FINISH;
            return this;
        }
        this.c = TimeUnit.MILLISECONDS.toSeconds(SystemClock.elapsedRealtime()) + this.a;
        this.d = 0L;
        Handler handler = this.e;
        handler.sendMessage(handler.obtainMessage(1));
        this.f = b.START;
        return this;
    }
}
