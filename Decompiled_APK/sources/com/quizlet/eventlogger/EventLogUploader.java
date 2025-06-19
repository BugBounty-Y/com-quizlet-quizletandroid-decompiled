package com.quizlet.eventlogger;

import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.transition.C1412o;
import com.amazon.device.ads.DtbDeviceDataRetriever;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import com.quizlet.api.IHttpErrorManager;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.eventlogger.EventLogUploader;
import com.quizlet.eventlogger.model.HashMapEventLog;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.observable.B;
import io.reactivex.rxjava3.internal.operators.observable.E;
import io.reactivex.rxjava3.internal.operators.single.g;
import io.reactivex.rxjava3.subjects.p;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.regex.Pattern;
import okhttp3.J;
import okhttp3.w;
import retrofit2.HttpException;
import retrofit2.K;

/* loaded from: classes2.dex */
public class EventLogUploader {
    private static IHttpErrorManager mHTTPErrorManager;
    private final ObjectReader mEventLogReader;
    private final EventFileWriter mFileWriter;
    private final File mFilesDirectory;
    private final Executor mFilesystemExecutor;
    private final o mLogUploadScheduler;
    private final ObjectWriter mObjectWriter;
    private final IQuizletApiClient mQuizletApiClient;
    private final IServerErrorListener mServerErrorListener;
    private final ObjectReader mServerResponseReader;
    private boolean syncInProgress;

    public final class LogUploadRequestDetails {
        public final String a;
        public final String b;

        public LogUploadRequestDetails(EventLogUploader eventLogUploader, String str, String str2) {
            this.a = str;
            this.b = str2;
        }
    }

    public final class LogUploadResponseDetails {
        public final String a;
        public final String b;

        public LogUploadResponseDetails(EventLogUploader eventLogUploader, String str, String str2) {
            this.a = str;
            this.b = str2;
        }
    }

    public final class LogUploadResult {
        public final ServerResponse a;

        public LogUploadResult(EventLogUploader eventLogUploader, ServerResponse serverResponse, boolean z) {
            this.a = serverResponse;
        }
    }

    public final class ParsedDetails {
        public final String a;
        public final List b;

        public ParsedDetails(EventLogUploader eventLogUploader, String str, List<HashMapEventLog> list) {
            this.a = str;
            this.b = list;
        }
    }

    public final class ServerResponse {
        public final String a;
        public final ApiThreeWrapper b;

        public ServerResponse(EventLogUploader eventLogUploader, String str, ApiThreeWrapper apiThreeWrapper) {
            this.a = str;
            this.b = apiThreeWrapper;
        }
    }

    public EventLogUploader(@NonNull IQuizletApiClient iQuizletApiClient, @NonNull Executor executor, @NonNull ObjectReader objectReader, @NonNull ObjectReader objectReader2, @NonNull ObjectWriter objectWriter, @NonNull File file, EventFileWriter eventFileWriter, @NonNull o oVar, @NonNull IServerErrorListener iServerErrorListener, @NonNull IHttpErrorManager iHttpErrorManager) {
        this.mQuizletApiClient = iQuizletApiClient;
        this.mServerResponseReader = objectReader2;
        this.mEventLogReader = objectReader;
        this.mObjectWriter = objectWriter;
        this.mFilesDirectory = file;
        this.mFilesystemExecutor = executor;
        this.mFileWriter = eventFileWriter;
        this.mLogUploadScheduler = oVar;
        this.mServerErrorListener = iServerErrorListener;
        mHTTPErrorManager = iHttpErrorManager;
    }

    public static void a(EventLogUploader eventLogUploader, p pVar) throws IOException {
        EventFileWriter eventFileWriter = eventLogUploader.mFileWriter;
        File file = eventLogUploader.mFilesDirectory;
        eventFileWriter.getClass();
        for (File file2 : file.listFiles()) {
            EventFileWriter eventFileWriter2 = eventLogUploader.mFileWriter;
            String name = file2.getName();
            eventFileWriter2.getClass();
            if (name != null) {
                String strConcat = "/".concat(name);
                if (!strConcat.startsWith("/quizlet-event-log-0.txt") && (strConcat.startsWith("/quizlet-event-rolled-log") || strConcat.startsWith("/quizlet-event-log"))) {
                    String absolutePath = file2.getAbsolutePath();
                    ArrayList arrayList = new ArrayList();
                    try {
                        BufferedReader bufferedReader = new BufferedReader(new FileReader(file2));
                        while (true) {
                            String line = bufferedReader.readLine();
                            if (line == null) {
                                break;
                            }
                            HashMapEventLog hashMapEventLog = (HashMapEventLog) eventLogUploader.mEventLogReader.readValue(line);
                            if (hashMapEventLog != null && !DtbDeviceDataRetriever.ORIENTATION_UNKNOWN.equals(hashMapEventLog.getAction())) {
                                arrayList.add(hashMapEventLog);
                            }
                        }
                        bufferedReader.close();
                    } catch (IOException e) {
                        timber.log.c.a.d("There was a problem extracting logs from the file %s", e.getMessage());
                    }
                    pVar.b(new ParsedDetails(eventLogUploader, absolutePath, arrayList));
                }
            }
        }
        pVar.onComplete();
    }

    public static i b(final EventLogUploader eventLogUploader, final LogUploadRequestDetails logUploadRequestDetails) {
        eventLogUploader.getClass();
        Pattern pattern = w.e;
        final int i = 0;
        g gVarG = eventLogUploader.mQuizletApiClient.q(C1412o.g(AbstractC3347h2.d("application/json"), logUploadRequestDetails.b)).l(eventLogUploader.mLogUploadScheduler).g(new h(eventLogUploader) { // from class: com.quizlet.eventlogger.f
            public final /* synthetic */ EventLogUploader b;

            {
                this.b = eventLogUploader;
            }

            @Override // io.reactivex.rxjava3.functions.h
            public final Object apply(Object obj) {
                switch (i) {
                    case 0:
                        EventLogUploader eventLogUploader2 = this.b;
                        eventLogUploader2.getClass();
                        return new EventLogUploader.LogUploadResponseDetails(eventLogUploader2, logUploadRequestDetails.a, ((J) ((K) obj).b).f());
                    default:
                        Throwable th = (Throwable) obj;
                        EventLogUploader eventLogUploader3 = this.b;
                        eventLogUploader3.getClass();
                        return io.reactivex.rxjava3.core.p.f(new EventLogUploader.LogUploadResponseDetails(eventLogUploader3, logUploadRequestDetails.a, th instanceof HttpException ? ((HttpException) th).c.c.f() : null));
                }
            }
        });
        final int i2 = 1;
        return new g(gVarG, new h(eventLogUploader) { // from class: com.quizlet.eventlogger.f
            public final /* synthetic */ EventLogUploader b;

            {
                this.b = eventLogUploader;
            }

            @Override // io.reactivex.rxjava3.functions.h
            public final Object apply(Object obj) {
                switch (i2) {
                    case 0:
                        EventLogUploader eventLogUploader2 = this.b;
                        eventLogUploader2.getClass();
                        return new EventLogUploader.LogUploadResponseDetails(eventLogUploader2, logUploadRequestDetails.a, ((J) ((K) obj).b).f());
                    default:
                        Throwable th = (Throwable) obj;
                        EventLogUploader eventLogUploader3 = this.b;
                        eventLogUploader3.getClass();
                        return io.reactivex.rxjava3.core.p.f(new EventLogUploader.LogUploadResponseDetails(eventLogUploader3, logUploadRequestDetails.a, th instanceof HttpException ? ((HttpException) th).c.c.f() : null));
                }
            }
        }, 2).m();
    }

    public static void c(LogUploadResult logUploadResult) {
        ServerResponse serverResponse = logUploadResult.a;
        ApiThreeWrapper apiThreeWrapper = serverResponse.b;
        if (apiThreeWrapper == null || apiThreeWrapper.getError() == null) {
            return;
        }
        IHttpErrorManager iHttpErrorManager = mHTTPErrorManager;
        ApiThreeWrapper apiThreeWrapper2 = serverResponse.b;
        if (iHttpErrorManager.b(apiThreeWrapper2.getError().getCode().intValue())) {
            timber.log.c.b(new RuntimeException(AbstractC0147y.d("Error in uploaded logs: ", apiThreeWrapper2.getError().getServerMessage())));
        }
    }

    public final void d(com.quizlet.background.eventlogging.a aVar) {
        boolean z;
        synchronized (this) {
            z = this.syncInProgress;
        }
        if (z) {
            return;
        }
        i(true);
        p pVarZ = p.z();
        this.mFilesystemExecutor.execute(new com.google.firebase.crashlytics.internal.common.i(20, this, pVarZ));
        final int i = 0;
        final int i2 = 1;
        i iVarM = pVarZ.w(this.mLogUploadScheduler).m(new h(this) { // from class: com.quizlet.eventlogger.d
            public final /* synthetic */ EventLogUploader b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.h
            public final Object apply(Object obj) {
                switch (i) {
                    case 0:
                        return this.b.h((EventLogUploader.ParsedDetails) obj);
                    case 1:
                        return EventLogUploader.b(this.b, (EventLogUploader.LogUploadRequestDetails) obj);
                    case 2:
                        return this.b.f((EventLogUploader.LogUploadResponseDetails) obj);
                    default:
                        return this.b.e((EventLogUploader.ServerResponse) obj);
                }
            }
        }, SubsamplingScaleImageView.TILE_SIZE_AUTO).m(new h(this) { // from class: com.quizlet.eventlogger.d
            public final /* synthetic */ EventLogUploader b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.h
            public final Object apply(Object obj) {
                switch (i2) {
                    case 0:
                        return this.b.h((EventLogUploader.ParsedDetails) obj);
                    case 1:
                        return EventLogUploader.b(this.b, (EventLogUploader.LogUploadRequestDetails) obj);
                    case 2:
                        return this.b.f((EventLogUploader.LogUploadResponseDetails) obj);
                    default:
                        return this.b.e((EventLogUploader.ServerResponse) obj);
                }
            }
        }, SubsamplingScaleImageView.TILE_SIZE_AUTO);
        final int i3 = 2;
        io.reactivex.rxjava3.internal.operators.observable.J jQ = iVarM.q(new h(this) { // from class: com.quizlet.eventlogger.d
            public final /* synthetic */ EventLogUploader b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.h
            public final Object apply(Object obj) {
                switch (i3) {
                    case 0:
                        return this.b.h((EventLogUploader.ParsedDetails) obj);
                    case 1:
                        return EventLogUploader.b(this.b, (EventLogUploader.LogUploadRequestDetails) obj);
                    case 2:
                        return this.b.f((EventLogUploader.LogUploadResponseDetails) obj);
                    default:
                        return this.b.e((EventLogUploader.ServerResponse) obj);
                }
            }
        });
        final int i4 = 3;
        B bI = jQ.q(new h(this) { // from class: com.quizlet.eventlogger.d
            public final /* synthetic */ EventLogUploader b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.h
            public final Object apply(Object obj) {
                switch (i4) {
                    case 0:
                        return this.b.h((EventLogUploader.ParsedDetails) obj);
                    case 1:
                        return EventLogUploader.b(this.b, (EventLogUploader.LogUploadRequestDetails) obj);
                    case 2:
                        return this.b.f((EventLogUploader.LogUploadResponseDetails) obj);
                    default:
                        return this.b.e((EventLogUploader.ServerResponse) obj);
                }
            }
        }).q(new com.quizlet.baserecyclerview.decoration.a(6)).i(new e(this, aVar));
        EventFileWriter eventFileWriter = this.mFileWriter;
        Objects.requireNonNull(eventFileWriter);
        e eVar = new e(eventFileWriter, 1);
        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.d;
        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
        new B(bI, gVar, gVar, eVar, bVar).u(new com.quizlet.billing.subscriptions.a(this, 3), new com.quizlet.billing.subscriptions.c(2), bVar);
    }

    public final LogUploadResult e(ServerResponse serverResponse) {
        String str;
        ApiThreeWrapper apiThreeWrapper = serverResponse.b;
        if (apiThreeWrapper == null || (!(apiThreeWrapper.getError() == null || mHTTPErrorManager.b(serverResponse.b.getError().getCode().intValue())) || (str = serverResponse.a) == null)) {
            return new LogUploadResult(this, serverResponse, false);
        }
        this.mFileWriter.getClass();
        return new LogUploadResult(this, serverResponse, new File(str).delete());
    }

    public final ServerResponse f(LogUploadResponseDetails logUploadResponseDetails) {
        ApiThreeWrapper apiThreeWrapper = null;
        try {
            String str = logUploadResponseDetails.b;
            if (str != null) {
                apiThreeWrapper = (ApiThreeWrapper) this.mServerResponseReader.readValue(str);
            }
        } catch (IOException | ClassCastException unused) {
            timber.log.c.a.d("Problem encountered when trying to parse server response: %s", logUploadResponseDetails.b);
        }
        return new ServerResponse(this, logUploadResponseDetails.a, apiThreeWrapper);
    }

    public final void g(LogUploadResult logUploadResult) {
        ApiThreeWrapper apiThreeWrapper;
        ServerResponse serverResponse = logUploadResult.a;
        this.mServerErrorListener.a((serverResponse == null || (apiThreeWrapper = serverResponse.b) == null || apiThreeWrapper.getError() == null || !mHTTPErrorManager.a(logUploadResult.a.b.getError().getCode().intValue())) ? false : true);
    }

    public final i h(ParsedDetails parsedDetails) {
        int size = parsedDetails.b.size();
        E e = E.a;
        String str = parsedDetails.a;
        if (size == 0) {
            this.mFileWriter.getClass();
            new File(str).delete();
            return e;
        }
        try {
            HashMap map = new HashMap();
            map.put("data", parsedDetails.b);
            return i.p(new LogUploadRequestDetails(this, str, this.mObjectWriter.writeValueAsString(map)));
        } catch (JsonProcessingException e2) {
            timber.log.c.a.f(e2, "There was an issue serializing the log objects while building the server request", new Object[0]);
            this.mFileWriter.getClass();
            new File(str).delete();
            return e;
        }
    }

    public final synchronized void i(boolean z) {
        this.syncInProgress = z;
    }
}
