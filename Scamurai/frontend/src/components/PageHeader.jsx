export default function PageHeader({ eyebrow, title, description, actions }) {
  return (
    <section className="page-header">
      <div className="page-header__content">
        <p className="eyebrow">{eyebrow || "Scamurai"}</p>
        <h1 className="page-title">{title}</h1>
        {description ? <p className="page-description">{description}</p> : null}
      </div>

      {actions ? <div>{actions}</div> : null}
    </section>
  );
}
