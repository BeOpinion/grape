(ns grape.hooks.auth-field)

(defn wrap-auth [op on-request-auth]
  (fn [deps resource request arg & _]
    (if (and (:auth-strategy resource)
             (not (op (:public-operations resource #{}))))
      (let [auth-strategy (:auth-strategy resource)
            auth-field? (= (:type auth-strategy) :field)
            doc-field (:doc-field auth-strategy)
            request-auth (:auth request)
            auth-value ((:auth-field auth-strategy) request-auth)]
        (if auth-field?
          (if (not request-auth)
            (throw (ex-info "Unauthorized" {:type :unauthorized}))
            (on-request-auth auth-value doc-field arg (get request :grape/existing)))
          arg))
      arg)))

(defn ^:private check-auth-access
  [doc-field auth-payload-value existing auth-value]
  (if (or (and existing
               (not= (str (get existing doc-field)) (str auth-value)))
          (and auth-payload-value
               (not= (str auth-payload-value) (str auth-value))))
    (throw (ex-info "Forbidden" {:type :forbidden}))
    auth-value))

(def hooks
  {:pre-create-pre-validate
   (wrap-auth :create (fn [auth-value doc-field payload & [_]]
                        (update-in payload [doc-field]
                                   (fn [existing-value]
                                     (if-not existing-value
                                       auth-value
                                       existing-value)))))
   :pre-create-post-validate
   (wrap-auth :create (fn [auth-value doc-field payload & [_]]
                        (update-in payload [doc-field]
                                   (fn [existing-value]
                                     (if (and existing-value (not= (str existing-value) (str auth-value)))
                                       (throw (ex-info "Forbidden" {:type :forbidden}))
                                       auth-value)))))
   :pre-update-pre-validate
   (wrap-auth :update (fn [auth-value doc-field payload & [existing]]
                        (update-in payload [doc-field]
                                   (fn [auth-payload-value]
                                     (check-auth-access doc-field auth-payload-value existing auth-value)))))
   :pre-update-post-validate
   (wrap-auth :update (fn [auth-value doc-field payload & [existing]]
                        (update-in payload [doc-field]
                                   (fn [auth-payload-value]
                                     (check-auth-access doc-field auth-payload-value existing auth-value)))))
   :pre-partial-update-pre-validate
   (wrap-auth :update (fn [auth-value doc-field payload & [existing]]
                        (update-in payload [doc-field]
                                   (fn [auth-payload-value]
                                     (check-auth-access doc-field auth-payload-value existing auth-value)))))
   :pre-partial-update-post-validate
   (wrap-auth :update (fn [auth-value doc-field payload & [existing]]
                        (update-in payload [doc-field]
                                   (fn [auth-payload-value]
                                     (check-auth-access doc-field auth-payload-value existing auth-value)))))
   :pre-read
   (wrap-auth :read (fn [auth-value doc-field query & [existing]]
                      (update-in query [:find]
                                 (fn [find]
                                   (let [existing-value (doc-field find)
                                         existing-value (if (and (get existing-value "$in") (= 1 (count (get existing-value "$in"))))
                                                          (first (get existing-value "$in"))
                                                          existing-value)]
                                     (if (and existing-value (not= (str existing-value) (str auth-value)))
                                       (throw (ex-info "Forbidden" {:type :forbidden}))
                                       (merge find {doc-field auth-value})))))))})
