package com.bumptech.glide.load.engine.executor;

import android.os.Process;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Unit;
import okio.C5088e;

/* loaded from: classes.dex */
public final class a extends Thread {
    public final /* synthetic */ int a = 0;

    public /* synthetic */ a(Runnable runnable) {
        super(runnable);
    }

    @Override // java.lang.Thread, java.lang.Runnable
    public void run() throws SecurityException, IllegalArgumentException {
        ReentrantLock reentrantLock;
        C5088e c5088eG;
        switch (this.a) {
            case 0:
                Process.setThreadPriority(9);
                super.run();
                return;
            case 1:
                Process.setThreadPriority(19);
                synchronized (this) {
                    while (true) {
                        try {
                            wait();
                        } catch (InterruptedException unused) {
                            return;
                        }
                    }
                }
            case 2:
            default:
                super.run();
                return;
            case 3:
                break;
        }
        while (true) {
            try {
                ReentrantLock reentrantLock2 = C5088e.h;
                reentrantLock = C5088e.h;
                reentrantLock.lock();
                try {
                    c5088eG = com.quizlet.quizletandroid.ui.common.images.capture.a.g();
                } finally {
                    reentrantLock.unlock();
                }
            } catch (InterruptedException unused2) {
                continue;
            }
            if (c5088eG == C5088e.l) {
                C5088e.l = null;
                return;
            }
            Unit unit = Unit.a;
            reentrantLock.unlock();
            if (c5088eG != null) {
                c5088eG.j();
            }
        }
    }

    public /* synthetic */ a(String str) {
        super(str);
    }

    public /* synthetic */ a(String str, Runnable runnable) {
        super(runnable, str);
    }

    public /* synthetic */ a(ThreadGroup threadGroup, String str) {
        super(threadGroup, str);
    }
}
