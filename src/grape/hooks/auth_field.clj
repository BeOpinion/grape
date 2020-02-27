(ns grape.hooks.auth-field)

(defn wrap-auth [op on-request-auth]
  (fn [_ resource request arg & [existing]]
    (if (and (:auth-strategy resource)
             (not (op (:public-operations resource #{}))))
      (let [auth-strategy (:auth-strategy resource)
            auth-field? (= (:type auth-strategy) :field)
            doc-field (:doc-field auth-strategy)
            request-auth (:auth request)
            auth-value ((:auth-field auth-strategy) request-auth)
            use-belongs-field? (:use-belongs-field auth-strategy false)]
        (if auth-field?
          (if (not request-auth)
            (throw (ex-info "Unauthorized" {:type :unauthorized}))
            (on-request-auth auth-value doc-field use-belongs-field? arg existing))
          arg))
      arg)))

(defn- -check-auth-on-update!
  [{:keys [doc-field auth-value use-belongs-field? payload existing]}]
  (let [doc (merge existing payload)
        doc-field-value (doc-field doc)]
    (if use-belongs-field?
      (let [belongs-value (-> (:belongs doc #{})
                              (conj doc-field-value))]
        (when-not (some? (belongs-value auth-value))
          (throw (ex-info "Forbidden" {:type :forbidden}))))
      (when-not (= doc-field-value auth-value)
        (throw (ex-info "Forbidden" {:type :forbidden}))))
    doc-field-value))

(def hooks
  {:pre-create-pre-validate
   (wrap-auth :create (fn [auth-value doc-field _ payload _]
                        (update-in payload [doc-field]
                                   (fn [existing-value]
                                     (if-not existing-value
                                       auth-value
                                       existing-value)))))
   :pre-create-post-validate
   (wrap-auth :create (fn [auth-value doc-field _ payload _]
                        (update-in payload [doc-field]
                                   (fn [existing-value]
                                     (if (and existing-value (not= (str existing-value) (str auth-value)))
                                       (throw (ex-info "Forbidden" {:type :forbidden}))
                                       auth-value)))))

   :pre-update-post-validate
   (wrap-auth :update (fn [auth-value doc-field use-belongs-field? payload existing]
                        (update-in payload [doc-field]
                                   (fn [_]
                                     (-check-auth-on-update!
                                       {:doc-field          doc-field
                                        :auth-value         auth-value
                                        :payload            payload
                                        :existing           existing
                                        :use-belongs-field? use-belongs-field?})))))

   :pre-partial-update-post-validate
   (wrap-auth :update (fn [auth-value doc-field use-belongs-field? payload existing]
                        (update-in payload [doc-field]
                                   (fn [_]
                                     (-check-auth-on-update!
                                       {:doc-field          doc-field
                                        :auth-value         auth-value
                                        :payload            payload
                                        :existing           existing
                                        :use-belongs-field? use-belongs-field?})))))
   :pre-read
   (wrap-auth :read (fn [auth-value doc-field use-belongs-field? query _]
                      (update-in query [:find]
                                 (fn [find]
                                   (if use-belongs-field?
                                     (merge (dissoc find doc-field :belongs) {:$or [{:belongs auth-value} {doc-field auth-value}]})
                                     (let [existing-value (doc-field find)
                                           existing-value (if (and (get existing-value "$in") (= 1 (count (get existing-value "$in"))))
                                                            (first (get existing-value "$in"))
                                                            existing-value)]
                                       (if (and existing-value (not= (str existing-value) (str auth-value)))
                                         (throw (ex-info "Forbidden" {:type :forbidden}))
                                         (merge find {doc-field auth-value}))))))))})
