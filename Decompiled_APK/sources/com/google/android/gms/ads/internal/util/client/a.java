package com.google.android.gms.ads.internal.util.client;

import com.android.billingclient.api.p;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public abstract class a {
    public static final ThreadPoolExecutor a = new ThreadPoolExecutor(2, SubsamplingScaleImageView.TILE_SIZE_AUTO, 10, TimeUnit.SECONDS, new SynchronousQueue(), new p("ClientDefault", 1));
    public static final ExecutorService b = Executors.newSingleThreadExecutor(new p("ClientSingle", 1));
}
